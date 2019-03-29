#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import inspect

import sys
from binascii import hexlify
from bitstring import BitArray
import json
from scapy.fields import ByteField, ShortField, MACField, BitField, IPField
from scapy.fields import IntField, StrFixedLenField, LongField, FieldListField, PacketLenField
from scapy.packet import Packet

from voltha.extensions.omci.omci_defs import OmciUninitializedFieldError, \
    AttributeAccess, OmciNullPointer, EntityOperations, OmciInvalidTypeError
from voltha.extensions.omci.omci_fields import OmciSerialNumberField, OmciTableField
from voltha.extensions.omci.omci_defs import bitpos_from_mask


class EntityClassAttribute(object):

    def __init__(self, fld, access=set(), optional=False, range_check=None,
                 avc=False, tca=False, counter=False, deprecated=False):
        """
        Initialize an Attribute for a Managed Entity Class

        :param fld: (Field) Scapy field type
        :param access: (AttributeAccess) Allowed access
        :param optional: (boolean) If true, attribute is option, else mandatory
        :param range_check: (callable) None, Lambda, or Function to validate value
        :param avc: (boolean) If true, an AVC notification can occur for the attribute
        :param tca: (boolean) If true, a threshold crossing alert alarm notification can occur
                              for the attribute
        :param counter: (boolean) If true, this attribute is a PM counter
        :param deprecated: (boolean) If true, this attribute is deprecated and
                           only 'read' operations (if-any) performed.
        """
        self._fld = fld
        self._access = access
        self._optional = optional
        self._range_check = range_check
        self._avc = avc
        self._tca = tca
        self._counter = counter
        self._deprecated = deprecated

    @property
    def field(self):
        return self._fld

    @property
    def access(self):
        return self._access

    @property
    def optional(self):
        return self._optional

    @property
    def is_counter(self):
        return self._counter

    @property
    def range_check(self):
        return self._range_check

    @property
    def avc_allowed(self):
        return self._avc

    @property
    def deprecated(self):
        return self._deprecated

    _type_checker_map = {
        'ByteField': lambda val: isinstance(val, (int, long)) and 0 <= val <= 0xFF,
        'ShortField': lambda val: isinstance(val, (int, long)) and 0 <= val <= 0xFFFF,
        'IntField': lambda val: isinstance(val, (int, long)) and 0 <= val <= 0xFFFFFFFF,
        'LongField': lambda val: isinstance(val, (int, long)) and 0 <= val <= 0xFFFFFFFFFFFFFFFF,
        'StrFixedLenField': lambda val: isinstance(val, basestring),
        'MACField': lambda val: True,   # TODO: Add a constraint for this field type
        'BitField': lambda val: True,   # TODO: Add a constraint for this field type
        'IPField': lambda val: True,    # TODO: Add a constraint for this field type
        'OmciTableField': lambda val: True,

        # TODO: As additional Scapy field types are used, add constraints
    }

    def valid(self, value):
        def _isa_lambda_function(v):
            import inspect
            return callable(v) and len(inspect.getargspec(v).args) == 1

        field_type = self.field.__class__.__name__
        type_check = EntityClassAttribute._type_checker_map.get(field_type,
                                                                lambda val: True)

        # TODO: Currently StrFixedLenField is used heavily for both bit fields as
        #       and other 'byte/octet' related strings that are NOT textual. Until
        #       all of these are corrected, 'StrFixedLenField' cannot test the type
        #       of the value provided

        if field_type != 'StrFixedLenField' and not type_check(value):
            return False

        if _isa_lambda_function(self.range_check):
            return self.range_check(value)
        return True


class EntityClassMeta(type):
    """
    Metaclass for EntityClass to generate secondary class attributes
    for class attributes of the derived classes.
    """
    def __init__(cls, name, bases, dct):
        super(EntityClassMeta, cls).__init__(name, bases, dct)

        # initialize attribute_name_to_index_map
        cls.attribute_name_to_index_map = dict(
            (a._fld.name, idx) for idx, a in enumerate(cls.attributes))


class EntityClass(object):

    class_id = 'to be filled by subclass'
    attributes = []
    mandatory_operations = set()
    optional_operations = set()
    notifications = set()
    alarms = dict()       # Alarm Number -> Alarm Name
    hidden = False        # If true, this attribute is not reported by a MIB upload.
                          # This attribute is needed to be able to properly perform
                          # MIB Audits.

    # will be map of attr_name -> index in attributes, initialized by metaclass
    attribute_name_to_index_map = None
    __metaclass__ = EntityClassMeta

    def __init__(self, **kw):
        assert(isinstance(kw, dict))
        for k, v in kw.iteritems():
            assert(k in self.attribute_name_to_index_map)
        self._data = kw

    def serialize(self, mask=None, operation=None):
        octets = ''

        # generate ordered list of attribute indices needed to be processed
        # if mask is provided, we use that explicitly
        # if mask is not provided, we determine attributes from the self._data
        # content also taking into account the type of operation in hand
        if mask is not None:
            attribute_indices = EntityClass.attribute_indices_from_mask(mask)
        else:
            attribute_indices = self.attribute_indices_from_data()

        # Serialize each indexed field (ignoring entity id)
        for index in attribute_indices:
            eca = self.attributes[index]
            field = eca.field
            try:
                value = self._data[field.name]

                if not eca.valid(value):
                    raise OmciInvalidTypeError(
                        'Value "{}" for Entity field "{}" is not valid'.format(value,
                                                                               field.name))
            except KeyError:
                raise OmciUninitializedFieldError(
                    'Entity field "{}" not set'.format(field.name))

            octets = field.addfield(None, octets, value)

        return octets

    def attribute_indices_from_data(self):
        return sorted(
            self.attribute_name_to_index_map[attr_name]
            for attr_name in self._data.iterkeys())

    byte1_mask_to_attr_indices = dict(
        (m, bitpos_from_mask(m, 8, -1)) for m in range(256))
    byte2_mask_to_attr_indices = dict(
        (m, bitpos_from_mask(m, 16, -1)) for m in range(256))

    @classmethod
    def attribute_indices_from_mask(cls, mask):
        # each bit in the 2-byte field denote an attribute index; we use a
        # lookup table to make lookup a bit faster
        return \
            cls.byte1_mask_to_attr_indices[(mask >> 8) & 0xff] + \
            cls.byte2_mask_to_attr_indices[(mask & 0xff)]

    @classmethod
    def mask_for(cls, *attr_names):
        """
        Return mask value corresponding to given attributes names
        :param attr_names: Attribute names
        :return: integer mask value
        """
        mask = 0
        for attr_name in attr_names:
            index = cls.attribute_name_to_index_map[attr_name]
            mask |= (1 << (16 - index))
        return mask


# abbreviations
ECA = EntityClassAttribute
AA = AttributeAccess
OP = EntityOperations


class OntData(EntityClass):
    class_id = 2
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),
        # Only 1 octet used if GET/SET operation
        ECA(ShortField("mib_data_sync", 0), {AA.R, AA.W})
    ]
    mandatory_operations = {OP.Get, OP.Set,
                            OP.GetAllAlarms, OP.GetAllAlarmsNext,
                            OP.MibReset, OP.MibUpload, OP.MibUploadNext}


class Cardholder(EntityClass):
    class_id = 5
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: 0 <= x < 255 or 256 <= x < 511,
            avc=True),
        ECA(ByteField("actual_plugin_unit_type", None), {AA.R}),
        ECA(ByteField("expected_plugin_unit_type", None), {AA.R, AA.W}),
        ECA(ByteField("expected_port_count", None), {AA.R, AA.W},
            optional=True),
        ECA(StrFixedLenField("expected_equipment_id", None, 20), {AA.R, AA.W},
            optional=True, avc=True),
        ECA(StrFixedLenField("actual_equipment_id", None, 20), {AA.R},
            optional=True),
        ECA(ByteField("protection_profile_pointer", None), {AA.R},
            optional=True),
        ECA(ByteField("invoke_protection_switch", None), {AA.R, AA.W},
            optional=True, range_check=lambda x: 0 <= x <= 3),
        ECA(ByteField("arc", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1, optional=True, avc=True),
        ECA(ByteField("arc_interval", 0), {AA.R, AA.W}, optional=True),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Plug-in circuit pack missing',
        1: 'Plug-in type mismatch alarm',
        2: 'Improper card removal',
        3: 'Plug-in equipment ID mismatch alarm',
        4: 'Protection switch',
    }


class CircuitPack(EntityClass):
    class_id = 6
    attributes = [
        ECA(StrFixedLenField("managed_entity_id", None, 22), {AA.R, AA.SBC},
            range_check=lambda x: 0 <= x < 255 or 256 <= x < 511),
        ECA(ByteField("type", None), {AA.R, AA.SBC}),
        ECA(ByteField("number_of_ports", None), {AA.R}, optional=True),
        ECA(OmciSerialNumberField("serial_number"), {AA.R}),
        ECA(StrFixedLenField("version", None, 14), {AA.R}),
        ECA(StrFixedLenField("vendor_id", None, 4), {AA.R}),
        ECA(ByteField("administrative_state", None), {AA.R, AA.W}),
        ECA(ByteField("operational_state", None), {AA.R}, optional=True, avc=True),
        ECA(ByteField("bridged_or_ip_ind", None), {AA.R, AA.W}, optional=True,
            range_check=lambda x: 0 <= x <= 2),
        ECA(StrFixedLenField("equipment_id", None, 20), {AA.R}, optional=True),
        ECA(ByteField("card_configuration", None), {AA.R, AA.W, AA.SBC},
            optional=True),  # not really mandatory, see spec ITU-T G.988, 9.1.6
        ECA(ByteField("total_tcont_buffer_number", None), {AA.R},
            optional=True),  # not really mandatory, see spec ITU-T G.988, 9.1.6
        ECA(ByteField("total_priority_queue_number", None), {AA.R},
            optional=True),  # not really mandatory, see spec ITU-T G.988, 9.1.6
        ECA(ByteField("total_traffic_scheduler_number", None), {AA.R},
            optional=True),  # not really mandatory, see spec ITU-T G.988, 9.1.6
        ECA(IntField("power_sched_override", None), {AA.R, AA.W},
            optional=True)
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Reboot}
    optional_operations = {OP.Create, OP.Delete, OP.Test}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Equipment alarm',
        1: 'Powering alarm',
        2: 'Self-test failure',
        3: 'Laser end of life',
        4: 'Temperature yellow',
        5: 'Temperature red',
    }

class SoftwareImage(EntityClass):
    class_id = 7
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: 0 <= x/256 <= 254 or 0 <= x % 256 <= 1),
        ECA(StrFixedLenField("version", None, 14), {AA.R}, avc=True),
        ECA(ByteField("is_committed", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("is_active", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("is_valid", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 1),
        ECA(StrFixedLenField("product_code", None, 25), {AA.R}, optional=True, avc=True),
        ECA(StrFixedLenField("image_hash", None, 16), {AA.R}, optional=True, avc=True),
    ]
    mandatory_operations = {OP.Get, OP.StartSoftwareDownload, OP.DownloadSection,
                            OP.EndSoftwareDownload, OP.ActivateSoftware,
                            OP.CommitSoftware}
    notifications = {OP.AttributeValueChange}


class PptpEthernetUni(EntityClass):
    class_id = 11
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ByteField("expected_type", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 254),
        ECA(ByteField("sensed_type", 0), {AA.R}, optional=True, avc=True),
        # TODO: For sensed_type AVC, see note in AT&T OMCI Specification, V3.0, page 123
        ECA(ByteField("autodetection_config", 0), {AA.R, AA.W},
            range_check=lambda x: x in [0, 1, 2, 3, 4, 5,
                                        0x10, 0x11, 0x12, 0x13, 0x14,
                                        0x20, 0x30], optional=True),  # See ITU-T G.988
        ECA(ByteField("ethernet_loopback_config", 0), {AA.R, AA.W},
            range_check=lambda x: x in [0, 3]),
        ECA(ByteField("administrative_state", 1), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("operational_state", 1), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1, optional=True, avc=True),
        ECA(ByteField("config_ind", 0), {AA.R},
            range_check=lambda x: x in [0, 1, 2, 3, 4, 0x11, 0x12, 0x13]),
        ECA(ShortField("max_frame_size", 1518), {AA.R, AA.W}, optional=True),
        ECA(ByteField("dte_dce_ind", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 2),
        ECA(ShortField("pause_time", 0), {AA.R, AA.W}, optional=True),
        ECA(ByteField("bridged_ip_ind", 2), {AA.R, AA.W},
            optional=True, range_check=lambda x: 0 <= x <= 2),
        ECA(ByteField("arc", 0), {AA.R, AA.W}, optional=True,
            range_check=lambda x: 0 <= x <= 1, avc=True),
        ECA(ByteField("arc_interval", 0), {AA.R, AA.W}, optional=True),
        ECA(ByteField("pppoe_filter", 0), {AA.R, AA.W}, optional=True),
        ECA(ByteField("power_control", 0), {AA.R, AA.W}, optional=True),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'LAN Loss Of Signal',
    }


class MacBridgeServiceProfile(EntityClass):
    class_id = 45
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("spanning_tree_ind", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("learning_ind", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("port_bridging_ind", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("priority", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("max_age", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0x0600 <= x <= 0x2800),
        ECA(ShortField("hello_time", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0x0100 <= x <= 0x0A00),
        ECA(ShortField("forward_delay", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0x0400 <= x <= 0x1E00),
        ECA(ByteField("unknown_mac_address_discard", None),
            {AA.R, AA.W, AA.SBC}, range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("mac_learning_depth", None),
            {AA.R, AA.W, AA.SBC}, optional=True),
        ECA(ByteField("dynamic_filtering_ageing_time", None),
            {AA.R, AA.W, AA.SBC}, optional=True),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}


class MacBridgePortConfigurationData(EntityClass):
    class_id = 47
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("bridge_id_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("port_num", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("tp_type", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 1 <= x <= 12),
        ECA(ShortField("tp_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("port_priority", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("port_path_cost", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("port_spanning_tree_in", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("encapsulation_methods", None), {AA.R, AA.W, AA.SBC},
            optional=True, deprecated=True),
        ECA(ByteField("lan_fcs_ind", None), {AA.R, AA.W, AA.SBC},
            optional=True, deprecated=True),
        ECA(MACField("port_mac_address", None), {AA.R}, optional=True),
        ECA(ShortField("outbound_td_pointer", None), {AA.R, AA.W},
            optional=True),
        ECA(ShortField("inbound_td_pointer", None), {AA.R, AA.W},
            optional=True),
        # TODO:
        ECA(ByteField("mac_learning_depth", 0), {AA.R, AA.W, AA.SBC},
            optional=True),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Port blocking',
    }


class MacBridgePortFilterPreAssignTable(EntityClass):
    class_id = 79
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("ipv4_multicast", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("ipv6_multicast", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("ipv4_broadcast", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("rarp", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("ipx", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("netbeui", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("appletalk", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("bridge_management_information", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("arp", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("pppoe_broadcast", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1)
    ]
    mandatory_operations = {OP.Get, OP.Set}


class VlanTaggingFilterData(EntityClass):
    class_id = 84
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(FieldListField("vlan_filter_list", None,
                           ShortField('', 0), count_from=lambda _: 12),
            {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("forward_operation", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0x00 <= x <= 0x21),
        ECA(ByteField("number_of_entries", None), {AA.R, AA.W, AA.SBC})
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}


class Ieee8021pMapperServiceProfile(EntityClass):
    class_id = 130
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("tp_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_0",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_1",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_2",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_3",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_4",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_5",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_6",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interwork_tp_pointer_for_p_bit_priority_7",
                       OmciNullPointer), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("unmarked_frame_option", None),
            {AA.R, AA.W, AA.SBC}, range_check=lambda x: 0 <= x <= 1),
        ECA(StrFixedLenField("dscp_to_p_bit_mapping", None, length=24),
            {AA.R, AA.W}),  # TODO: Would a custom 3-bit group bitfield work better?
        ECA(ByteField("default_p_bit_marking", None),
            {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("tp_type", None), {AA.R, AA.W, AA.SBC},
            optional=True, range_check=lambda x: 0 <= x <= 8)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}


class OltG(EntityClass):
    class_id = 131
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),
        ECA(StrFixedLenField("olt_vendor_id", None, 4), {AA.R, AA.W}),
        ECA(StrFixedLenField("equipment_id", None, 20), {AA.R, AA.W}),
        ECA(StrFixedLenField("version", None, 14), {AA.R, AA.W}),
        ECA(StrFixedLenField("time_of_day", None, 14), {AA.R, AA.W})
    ]
    mandatory_operations = {OP.Get, OP.Set}


class OntPowerShedding(EntityClass):
    class_id = 133
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),
        ECA(ShortField("restore_power_time_reset_interval", 0),
            {AA.R, AA.W}),
        ECA(ShortField("data_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("voice_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("video_overlay_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("video_return_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("dsl_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("atm_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("ces_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("frame_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("sonet_class_shedding_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("shedding_status", None), {AA.R, AA.W}, optional=True,
            avc=True),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange}


class IpHostConfigData(EntityClass):
    class_id = 134
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(BitField("ip_options", 0, size=8), {AA.R, AA.W}),
        ECA(MACField("mac_address", None), {AA.R}),
        ECA(StrFixedLenField("onu_identifier", None, 25), {AA.R, AA.W}),
        ECA(IPField("ip_address", None), {AA.R, AA.W}),
        ECA(IPField("mask", None), {AA.R, AA.W}),
        ECA(IPField("gateway", None), {AA.R, AA.W}),
        ECA(IPField("primary_dns", None), {AA.R, AA.W}),
        ECA(IPField("secondary_dns", None), {AA.R, AA.W}),
        ECA(IPField("current_address", None), {AA.R}, avc=True),
        ECA(IPField("current_mask", None), {AA.R}, avc=True),
        ECA(IPField("current_gateway", None), {AA.R}, avc=True),
        ECA(IPField("current_primary_dns", None), {AA.R}, avc=True),
        ECA(IPField("current_secondary_dns", None), {AA.R}, avc=True),
        ECA(StrFixedLenField("domain_name", None, 25), {AA.R}, avc=True),
        ECA(StrFixedLenField("host_name", None, 25), {AA.R}, avc=True),
        ECA(ShortField("relay_agent_options", None), {AA.R, AA.W},
            optional=True),
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Test}
    notifications = {OP.AttributeValueChange}


class VlanTaggingOperation(Packet):
    name = "VlanTaggingOperation"
    fields_desc = [
        BitField("filter_outer_priority", 0, 4),
        BitField("filter_outer_vid", 0, 13),
        BitField("filter_outer_tpid_de", 0, 3),
        BitField("pad1", 0, 12),

        BitField("filter_inner_priority", 0, 4),
        BitField("filter_inner_vid", 0, 13),
        BitField("filter_inner_tpid_de", 0, 3),
        BitField("pad2", 0, 8),
        BitField("filter_ether_type", 0, 4),

        BitField("treatment_tags_to_remove", 0, 2),
        BitField("pad3", 0, 10),
        BitField("treatment_outer_priority", 0, 4),
        BitField("treatment_outer_vid", 0, 13),
        BitField("treatment_outer_tpid_de", 0, 3),

        BitField("pad4", 0, 12),
        BitField("treatment_inner_priority", 0, 4),
        BitField("treatment_inner_vid", 0, 13),
        BitField("treatment_inner_tpid_de", 0, 3),
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))

    @staticmethod
    def json_from_value(value):
        bits = BitArray(hex=hexlify(value))
        temp = VlanTaggingOperation(
            filter_outer_priority=bits[0:4].uint,         # 4  <-size
            filter_outer_vid=bits[4:17].uint,             # 13
            filter_outer_tpid_de=bits[17:20].uint,        # 3
                                                          # pad 12
            filter_inner_priority=bits[32:36].uint,       # 4
            filter_inner_vid=bits[36:49].uint,            # 13
            filter_inner_tpid_de=bits[49:52].uint,        # 3
                                                          # pad 8
            filter_ether_type=bits[60:64].uint,           # 4
            treatment_tags_to_remove=bits[64:66].uint,    # 2
                                                          # pad 10
            treatment_outer_priority=bits[76:80].uint,    # 4
            treatment_outer_vid=bits[80:93].uint,         # 13
            treatment_outer_tpid_de=bits[93:96].uint,     # 3
                                                          # pad 12
            treatment_inner_priority=bits[108:112].uint,  # 4
            treatment_inner_vid=bits[112:125].uint,       # 13
            treatment_inner_tpid_de=bits[125:128].uint,   # 3
        )
        return json.dumps(temp.fields, separators=(',', ':'))

    def index(self):
        return '{:02}'.format(self.fields.get('filter_outer_priority',0)) + \
               '{:03}'.format(self.fields.get('filter_outer_vid',0)) + \
               '{:01}'.format(self.fields.get('filter_outer_tpid_de',0)) + \
               '{:03}'.format(self.fields.get('filter_inner_priority',0)) + \
               '{:04}'.format(self.fields.get('filter_inner_vid',0)) + \
               '{:01}'.format(self.fields.get('filter_inner_tpid_de',0)) + \
               '{:02}'.format(self.fields.get('filter_ether_type',0))

    def is_delete(self):
        return self.fields.get('treatment_tags_to_remove',0) == 0x3 and \
            self.fields.get('pad3',0) == 0x3ff and \
            self.fields.get('treatment_outer_priority',0) == 0xf and \
            self.fields.get('treatment_outer_vid',0) == 0x1fff and \
            self.fields.get('treatment_outer_tpid_de',0) == 0x7 and \
            self.fields.get('pad4',0) == 0xfff and \
            self.fields.get('treatment_inner_priority',0) == 0xf and \
            self.fields.get('treatment_inner_vid',0) == 0x1fff and \
            self.fields.get('treatment_inner_tpid_de',0) == 0x7

    def delete(self):
        self.fields['treatment_tags_to_remove'] = 0x3
        self.fields['pad3'] = 0x3ff
        self.fields['treatment_outer_priority'] = 0xf
        self.fields['treatment_outer_vid'] = 0x1fff
        self.fields['treatment_outer_tpid_de'] = 0x7
        self.fields['pad4'] = 0xfff
        self.fields['treatment_inner_priority'] = 0xf
        self.fields['treatment_inner_vid'] = 0x1fff
        self.fields['treatment_inner_tpid_de'] = 0x7
        return self


class ExtendedVlanTaggingOperationConfigurationData(EntityClass):
    class_id = 171
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("association_type", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 11),
        ECA(ShortField("received_vlan_tagging_operation_table_max_size", None),
            {AA.R}),
        ECA(ShortField("input_tpid", None), {AA.R, AA.W}),
        ECA(ShortField("output_tpid", None), {AA.R, AA.W}),
        ECA(ByteField("downstream_mode", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 8),
        ECA(OmciTableField(
            PacketLenField("received_frame_vlan_tagging_operation_table", None,
                VlanTaggingOperation, length_from=lambda pkt: 16)), {AA.R, AA.W}),
        ECA(ShortField("associated_me_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(FieldListField("dscp_to_p_bit_mapping", None,
                           BitField('',  0, size=3), count_from=lambda _: 64),
            {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Set, OP.Get, OP.GetNext}
    optional_operations = {OP.SetTable}


class OntG(EntityClass):
    class_id = 256
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),
        ECA(StrFixedLenField("vendor_id", None, 4), {AA.R}),
        ECA(StrFixedLenField("version", None, 14), {AA.R}),
        ECA(OmciSerialNumberField("serial_number"), {AA.R}),
        ECA(ByteField("traffic_management_options", None), {AA.R},
            range_check=lambda x: 0 <= x <= 2),
        ECA(ByteField("vp_vc_cross_connection_option", 0), {AA.R},
            optional=True, deprecated=True),
        ECA(ByteField("battery_backup", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("administrative_state", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("operational_state", None), {AA.R}, optional=True,
            range_check=lambda x: 0 <= x <= 1, avc=True),
        ECA(ByteField("ont_survival_time", None), {AA.R}, optional=True),
        ECA(StrFixedLenField("logical_onu_id", None, 24), {AA.R},
            optional=True, avc=True),
        ECA(StrFixedLenField("logical_password", None, 12), {AA.R},
            optional=True, avc=True),
        ECA(ByteField("credentials_status", None), {AA.R, AA.W},
            optional=True, range_check=lambda x: 0 <= x <= 4),
        ECA(BitField("extended_tc_layer_options", None, size=16), {AA.R},
            optional=True),
    ]
    mandatory_operations = {
        OP.Get, OP.Set, OP.Reboot, OP.Test, OP.SynchronizeTime}
    notifications = {OP.TestResult, OP.AttributeValueChange,
                     OP.AlarmNotification}
    alarms = {
        0: 'Equipment alarm',
        1: 'Powering alarm',
        2: 'Battery missing',
        3: 'Battery failure',
        4: 'Battery low',
        5: 'Physical intrusion',
        6: 'Self-test failure',
        7: 'Dying gasp',
        8: 'Temperature yellow',
        9: 'Temperature red',
        10: 'Voltage yellow',
        11: 'Voltage red',
        12: 'ONU manual power off',
        13: 'Invalid image',
        14: 'PSE overload yellow',
        15: 'PSE overload red',
    }


class Ont2G(EntityClass):
    class_id = 257
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),
        ECA(StrFixedLenField("equipment_id", None, 20), {AA.R}),
        ECA(ByteField("omcc_version", None), {AA.R}, avc=True),
        ECA(ShortField("vendor_product_code", None), {AA.R}),
        ECA(ByteField("security_capability", None), {AA.R},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("security_mode", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("total_priority_queue_number", None), {AA.R}),
        ECA(ByteField("total_traffic_scheduler_number", None), {AA.R}),
        ECA(ByteField("mode", None), {AA.R}, deprecated=True),
        ECA(ShortField("total_gem_port_id_number", None), {AA.R}),
        ECA(IntField("sys_uptime", None), {AA.R}),
        ECA(BitField("connectivity_capability", None, size=16), {AA.R}),
        ECA(ByteField("current_connectivity_mode", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 7),
        ECA(BitField("qos_configuration_flexibility", None, size=16),
            {AA.R}, optional=True),
        ECA(ShortField("priority_queue_scale_factor", None), {AA.R, AA.W},
            optional=True),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange}


class Tcont(EntityClass):
    class_id = 262
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ShortField("alloc_id", None), {AA.R, AA.W}),
        ECA(ByteField("mode_indicator", 1), {AA.R}, deprecated=True),
        ECA(ByteField("policy", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 2),
    ]
    mandatory_operations = {OP.Get, OP.Set}


class AniG(EntityClass):
    class_id = 263
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ByteField("sr_indication", None), {AA.R}),
        ECA(ShortField("total_tcont_number", None), {AA.R}),
        ECA(ShortField("gem_block_length", None), {AA.R, AA.W}),
        ECA(ByteField("piggyback_dba_reporting", None), {AA.R},
            range_check=lambda x: 0 <= x <= 4),
        ECA(ByteField("whole_ont_dba_reporting", None), {AA.R},
            deprecated=True),
        ECA(ByteField("sf_threshold", 5), {AA.R, AA.W}),
        ECA(ByteField("sd_threshold", 9), {AA.R, AA.W}),
        ECA(ByteField("arc", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1, avc=True),
        ECA(ByteField("arc_interval", 0), {AA.R, AA.W}),
        ECA(ShortField("optical_signal_level", None), {AA.R}),
        ECA(ByteField("lower_optical_threshold", 0xFF), {AA.R, AA.W}),
        ECA(ByteField("upper_optical_threshold", 0xFF), {AA.R, AA.W}),
        ECA(ShortField("ont_response_time", None), {AA.R}),
        ECA(ShortField("transmit_optical_level", None), {AA.R}),
        ECA(ByteField("lower_transmit_power_threshold", 0x81), {AA.R, AA.W}),
        ECA(ByteField("upper_transmit_power_threshold", 0x81), {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Test}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Low received optical power',
        1: 'High received optical power',
        2: 'Signal fail',
        3: 'Signal degrade',
        4: 'Low transmit optical power',
        5: 'High transmit optical power',
        6: 'Laser bias current',
    }


class UniG(EntityClass):
    class_id = 264
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ShortField("configuration_option_status", None), {AA.R, AA.W},
            deprecated=True),
        ECA(ByteField("administrative_state", None), {AA.R, AA.W}),
        ECA(ByteField("management_capability", None), {AA.R},
            range_check=lambda x: 0 <= x <= 2),
        ECA(ShortField("non_omci_management_identifier", None), {AA.R, AA.W}),
        ECA(ShortField("relay_agent_options", None), {AA.R, AA.W},
            optional=True),
    ]
    mandatory_operations = {OP.Get, OP.Set}


class GemInterworkingTp(EntityClass):
    class_id = 266
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("gem_port_network_ctp_pointer", None),
            {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("interworking_option", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 7),
        ECA(ShortField("service_profile_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interworking_tp_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("pptp_counter", None), {AA.R}, optional=True),
        ECA(ByteField("operational_state", None), {AA.R}, optional=True,
            range_check=lambda x: 0 <= x <= 1, avc=True),
        ECA(ShortField("gal_profile_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("gal_loopback_configuration", 0),
            {AA.R, AA.W}, range_check=lambda x: 0 <= x <= 1),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        6: 'Operational state change',
    }


class GemPortNetworkCtp(EntityClass):
    class_id = 268
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("port_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("tcont_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("direction", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 1 <= x <= 3),
        ECA(ShortField("traffic_management_pointer_upstream", None),
            {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("traffic_descriptor_profile_pointer", None),
            {AA.R, AA.W, AA.SBC}, optional=True),
        ECA(ByteField("uni_counter", None), {AA.R}, optional=True),
        ECA(ShortField("priority_queue_pointer_downstream", None),
            {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("encryption_state", None), {AA.R}, optional=True),
        ECA(ShortField("traffic_desc_profile_pointer_downstream", None),
            {AA.R, AA.W, AA.SBC}, optional=True),
        ECA(ShortField("encryption_key_ring", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 3)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    notifications = {OP.AlarmNotification}
    alarms = {
        5: 'End-to-end loss of continuity',
    }


class GalEthernetProfile(EntityClass):
    class_id = 272
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ShortField("max_gem_payload_size", None), {AA.R, AA.W, AA.SBC}),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}


class PriorityQueueG(EntityClass):
    class_id = 277
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ByteField("queue_configuration_option", None), {AA.R},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("maximum_queue_size", None), {AA.R}),
        ECA(ShortField("allocated_queue_size", None), {AA.R, AA.W}),
        ECA(ShortField("discard_block_counter_reset_interval", None), {AA.R, AA.W}),
        ECA(ShortField("threshold_value_for_discarded_blocks", None), {AA.R, AA.W}),
        ECA(IntField("related_port", None), {AA.R, AA.W}),
        ECA(ShortField("traffic_scheduler_pointer", 0), {AA.R, AA.W}),
        ECA(ByteField("weight", 1), {AA.R, AA.W}),
        ECA(ShortField("back_pressure_operation", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(IntField("back_pressure_time", 0), {AA.R, AA.W}),
        ECA(ShortField("back_pressure_occur_queue_threshold", None), {AA.R, AA.W}),
        ECA(ShortField("back_pressure_clear_queue_threshold", None), {AA.R, AA.W}),
        # TODO: Custom field of 4 2-byte values would help below
        ECA(LongField("packet_drop_queue_thresholds", None), {AA.R, AA.W},
            optional=True),
        ECA(ShortField("packet_drop_max_p", 0xFFFF), {AA.R, AA.W}, optional=True),
        ECA(ByteField("queue_drop_w_q", 9), {AA.R, AA.W}, optional=True),
        ECA(ByteField("drop_precedence_colour_marking", 0), {AA.R, AA.W},
            optional=True, range_check=lambda x: 0 <= x <= 7),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Block loss',
    }


class TrafficSchedulerG(EntityClass):
    class_id = 278
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ShortField("tcont_pointer", None), {AA.R}),
        ECA(ShortField("traffic_scheduler_pointer", None), {AA.R}),
        ECA(ByteField("policy", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 2),
        ECA(ByteField("priority_weight", 0), {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Get, OP.Set}


class MulticastGemInterworkingTp(EntityClass):
    class_id = 281
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC},
            range_check=lambda x: x != OmciNullPointer),
        ECA(ShortField("gem_port_network_ctp_pointer", None), {AA.R, AA.SBC}),
        ECA(ByteField("interworking_option", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: x in [0, 1, 3, 5]),
        ECA(ShortField("service_profile_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("interworking_tp_pointer", 0), {AA.R, AA.W, AA.SBC},
            deprecated=True),
        ECA(ByteField("pptp_counter", None), {AA.R}),
        ECA(ByteField("operational_state", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("gal_profile_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("gal_loopback_configuration", None), {AA.R, AA.W, AA.SBC},
            deprecated=True),
        # TODO add multicast_address_table here (page 85 of spec.)
        # ECA(...("multicast_address_table", None), {AA.R, AA.W})
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.GetNext, OP.Set}
    optional_operations = {OP.SetTable}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Deprecated',
    }


class AccessControlRow0(Packet):
    name = "AccessControlRow0"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("row_part_id", 0, 3),
        BitField("test", 0, 1),
        BitField("row_key", 0, 10),

        ShortField("gem_port_id", None),
        ShortField("vlan_id", None),
        IPField("src_ip", None),
        IPField("dst_ip_start", None),
        IPField("dst_ip_end", None),
        IntField("ipm_group_bw", None),
        ShortField("reserved0", 0)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class AccessControlRow1(Packet):
    name = "AccessControlRow1"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("row_part_id", 0, 3),
        BitField("test", 0, 1),
        BitField("row_key", 0, 10),

        StrFixedLenField("ipv6_src_addr_start_bytes", None, 12),
        ShortField("preview_length", None),
        ShortField("preview_repeat_time", None),
        ShortField("preview_repeat_count", None),
        ShortField("preview_reset_time", None),
        ShortField("reserved1", 0)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class AccessControlRow2(Packet):
    name = "AccessControlRow2"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("row_part_id", 0, 3),
        BitField("test", 0, 1),
        BitField("row_key", 0, 10),

        StrFixedLenField("ipv6_dst_addr_start_bytes", None, 12),
        StrFixedLenField("reserved2", None, 10)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class DownstreamIgmpMulticastTci(Packet):
    name = "DownstreamIgmpMulticastTci"
    fields_desc = [
        ByteField("ctrl_type", None),
        ShortField("tci", None)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class MulticastOperationsProfile(EntityClass):
    class_id = 309
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC},
            range_check=lambda x: x != 0 and x != OmciNullPointer),
        ECA(ByteField("igmp_version", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: x in [1, 2, 3, 16, 17]),
        ECA(ByteField("igmp_function", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 2),
        ECA(ByteField("immediate_leave", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("us_igmp_tci", None), {AA.R, AA.W, AA.SBC}, optional=True),
        ECA(ByteField("us_igmp_tag_ctrl", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 3, optional=True),
        ECA(IntField("us_igmp_rate", None), {AA.R, AA.W, AA.SBC}, optional=True),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "dynamic_access_control_list_table", None, 24), {AA.R, AA.W}),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "static_access_control_list_table", None, 24), {AA.R, AA.W}),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField("lost_groups_list_table", None, 10), {AA.R}),
        ECA(ByteField("robustness", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("querier_ip", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("query_interval", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("querier_max_response_time", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("last_member_response_time", 10), {AA.R, AA.W}),
        ECA(ByteField("unauthorized_join_behaviour", None), {AA.R, AA.W}),
        ECA(StrFixedLenField("ds_igmp_mcast_tci", None, 3), {AA.R, AA.W, AA.SBC}, optional=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Set, OP.Get, OP.GetNext}
    optional_operations = {OP.SetTable}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Lost multicast group',
    }


class MulticastServicePackage(Packet):
    name = "MulticastServicePackage"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("reserved0", 0, 4),
        BitField("row_key", 0, 10),

        ShortField("vid_uni", None),
        ShortField("max_simultaneous_groups", None),
        IntField("max_multicast_bw", None),
        ShortField("mcast_operations_profile_pointer", None),
        StrFixedLenField("reserved1", None, 8)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class AllowedPreviewGroupsRow0(Packet):
    name = "AllowedPreviewGroupsRow0"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("row_part_id", 0, 3),
        BitField("reserved0", 0, 1),
        BitField("row_key", 0, 10),

        StrFixedLenField("ipv6_pad", 0, 12),
        IPField("src_ip", None),
        ShortField("vlan_id_ani", None),
        ShortField("vlan_id_uni", None)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class AllowedPreviewGroupsRow1(Packet):
    name = "AllowedPreviewGroupsRow1"
    fields_desc = [
        BitField("set_ctrl", 0, 2),
        BitField("row_part_id", 0, 3),
        BitField("reserved0", 0, 1),
        BitField("row_key", 0, 10),

        StrFixedLenField("ipv6_pad", 0, 12),
        IPField("dst_ip", None),
        ShortField("duration", None),
        ShortField("time_left", None)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))


class MulticastSubscriberConfigInfo(EntityClass):
    class_id = 310
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("me_type", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ShortField("mcast_operations_profile_pointer", None),
            {AA.R, AA.W, AA.SBC}),
        ECA(ShortField("max_simultaneous_groups", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("max_multicast_bandwidth", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("bandwidth_enforcement", None), {AA.R, AA.W, AA.SBC},
            range_check=lambda x: 0 <= x <= 1),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "multicast_service_package_table", None, 20), {AA.R, AA.W}),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "allowed_preview_groups_table", None, 22), {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Set, OP.Get, OP.GetNext,
                            OP.SetTable}


class VirtualEthernetInterfacePt(EntityClass):
    class_id = 329
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x != 0 and x != OmciNullPointer),
        ECA(ByteField("administrative_state", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("operational_state", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 1),
        ECA(StrFixedLenField(
            "interdomain_name", None, 25), {AA.R, AA.W}, optional=True),
        ECA(ShortField("tcp_udp_pointer", None), {AA.R, AA.W}, optional=True),
        ECA(ShortField("iana_assigned_port", None), {AA.R}),
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Connecting function fail',
    }


class OmciMeTypeTable(Packet):
    """
    OMCI ME Supported Types Table
    """
    name = "OmciMeTypeTable"
    fields_desc = [
        ShortField("me_type", None)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))

    @staticmethod
    def json_from_value(value):
        data = int(value)
        temp = OmciMeTypeTable(me_type=data)
        return json.dumps(temp.fields, separators=(',', ':'))

    def index(self):
        return '{:04}'.format(self.fields.get('me_type', 0))

    def is_delete(self):
        return self.fields.get('me_type', 0) == 0

    def delete(self):
        self.fields['me_type'] = 0
        return self


class OmciMsgTypeTable(Packet):
    """
    OMCI Supported Message Types Table
    """
    name = "OmciMsgTypeTable"
    fields_desc = [
        ByteField("msg_type", None)
    ]

    def to_json(self):
        return json.dumps(self.fields, separators=(',', ':'))

    @staticmethod
    def json_from_value(value):
        data = int(value)
        temp = OmciMeTypeTable(me_type=data)
        return json.dumps(temp.fields, separators=(',', ':'))

    def index(self):
        return '{:02}'.format(self.fields.get('msg_type', 0))

    def is_delete(self):
        return self.fields.get('me_type', 0) == 0

    def delete(self):
        self.fields['me_type'] = 0
        return self


class Omci(EntityClass):
    class_id = 287
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R},
            range_check=lambda x: x == 0),

        ECA(OmciTableField(
            PacketLenField("me_type_table", None,
                           OmciMeTypeTable, length_from=lambda pkt: 2)),
            {AA.R}),

        ECA(OmciTableField(
            PacketLenField("message_type_table", None,
                           OmciMsgTypeTable, length_from=lambda pkt: 1)),
            {AA.R}),
    ]
    mandatory_operations = {OP.Get, OP.GetNext}


class EnhSecurityControl(EntityClass):
    class_id = 332
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(BitField("olt_crypto_capabilities", None, 16*8), {AA.W}),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "olt_random_challenge_table", None, 17), {AA.R, AA.W}),
        ECA(ByteField("olt_challenge_status", 0), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("onu_selected_crypto_capabilities", None), {AA.R}),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "onu_random_challenge_table", None, 16), {AA.R}, avc=True),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "onu_authentication_result_table", None, 16), {AA.R}, avc=True),
        # TODO: need to make table and add column data
        ECA(StrFixedLenField(
            "olt_authentication_result_table", None, 17), {AA.W}),
        ECA(ByteField("olt_result_status", None), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("onu_authentication_status", None), {AA.R}, avc=True,
            range_check=lambda x: 0 <= x <= 5),
        ECA(StrFixedLenField(
            "master_session_key_name", None, 16), {AA.R}),
        ECA(StrFixedLenField(
            "broadcast_key_table", None, 18), {AA.R, AA.W}),
        ECA(ShortField("effective_key_length", None), {AA.R}),

    ]
    mandatory_operations = {OP.Set, OP.Get, OP.GetNext}
    notifications = {OP.AttributeValueChange}


class EthernetPMMonitoringHistoryData(EntityClass):
    class_id = 24
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("fcs_errors", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("excessive_collision_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("late_collision_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("frames_too_long", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("buffer_overflows_on_rx", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("buffer_overflows_on_tx", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("single_collision_frame_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("multiple_collisions_frame_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("sqe_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("deferred_tx_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("internal_mac_tx_error_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("carrier_sense_error_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("alignment_error_counter", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("internal_mac_rx_error_counter", None), {AA.R}, tca=True, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set, OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'FCS errors',
        1: 'Excessive collision counter',
        2: 'Late collision counter',
        3: 'Frames too long',
        4: 'Buffer overflows on receive',
        5: 'Buffer overflows on transmit',
        6: 'Single collision frame counter',
        7: 'Multiple collision frame counter',
        8: 'SQE counter',
        9: 'Deferred transmission counter',
        10: 'Internal MAC transmit error counter',
        11: 'Carrier sense error counter',
        12: 'Alignment error counter',
        13: 'Internal MAC receive error counter',
    }


class FecPerformanceMonitoringHistoryData(EntityClass):
    class_id = 312
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("corrected_bytes", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("corrected_code_words", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("uncorrectable_code_words", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("total_code_words", None), {AA.R}, counter=True),
        ECA(ShortField("fec_seconds", None), {AA.R}, tca=True, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set, OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Corrected bytes',
        1: 'Corrected code words',
        2: 'Uncorrectable code words',
        4: 'FEC seconds',
    }


class EthernetFrameDownstreamPerformanceMonitoringHistoryData(EntityClass):
    class_id = 321
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("drop_events", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("octets", None), {AA.R}, counter=True),
        ECA(IntField("packets", None), {AA.R}, counter=True),
        ECA(IntField("broadcast_packets", None), {AA.R}, counter=True),
        ECA(IntField("multicast_packets", None), {AA.R}, counter=True),
        ECA(IntField("crc_errored_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("undersize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("oversize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("64_octets", None), {AA.R}, counter=True),
        ECA(IntField("65_to_127_octets", None), {AA.R}, counter=True),
        ECA(IntField("128_to_255_octets", None), {AA.R}, counter=True),
        ECA(IntField("256_to_511_octets", None), {AA.R}, counter=True),
        ECA(IntField("512_to_1023_octets", None), {AA.R}, counter=True),
        ECA(IntField("1024_to_1518_octets", None), {AA.R}, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set, OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    }


class EthernetFrameUpstreamPerformanceMonitoringHistoryData(EntityClass):
    class_id = 322
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("drop_events", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("octets", None), {AA.R}, counter=True),
        ECA(IntField("packets", None), {AA.R}, counter=True),
        ECA(IntField("broadcast_packets", None), {AA.R}, counter=True),
        ECA(IntField("multicast_packets", None), {AA.R}, counter=True),
        ECA(IntField("crc_errored_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("undersize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("oversize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("64_octets", None), {AA.R}, counter=True),
        ECA(IntField("65_to_127_octets", None), {AA.R}, counter=True),
        ECA(IntField("128_to_255_octets", None), {AA.R}, counter=True),
        ECA(IntField("256_to_511_octets", None), {AA.R}, counter=True),
        ECA(IntField("512_to_1023_octets", None), {AA.R}, counter=True),
        ECA(IntField("1024_to_1518_octets", None), {AA.R}, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set, OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    }


class VeipUni(EntityClass):
    class_id = 329
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R}),
        ECA(ByteField("administrative_state", 1), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1),
        ECA(ByteField("operational_state", 1), {AA.R, AA.W},
            range_check=lambda x: 0 <= x <= 1, optional=True, avc=True),
        ECA(StrFixedLenField("interdomain_name", None, 25), {AA.R, AA.W},
            optional=True),
        ECA(ShortField("tcp_udp_pointer", None), {AA.R, AA.W}, optional=True),
        ECA(ShortField("iana_assigned_port", 0xFFFF), {AA.R})
    ]
    mandatory_operations = {OP.Get, OP.Set}
    notifications = {OP.AttributeValueChange, OP.AlarmNotification}
    alarms = {
        0: 'Connecting function fail'
    }


class EthernetFrameExtendedPerformanceMonitoring(EntityClass):
    class_id = 334
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        # 2-octet field -> Threshold data 1/2 ID
        # 2-octet field -> Parent ME Class
        # 2-octet field -> Parent ME Instance
        # 2-octet field -> Accumulation disable
        # 2-octet field -> TCA Disable
        # 2-octet field -> Control fields bitmap
        # 2-octet field -> TCI
        # 2-octet field -> Reserved
        ECA(FieldListField("control_block", None, ShortField('', 0),
                           count_from=lambda _: 8), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("drop_events", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("octets", None), {AA.R}, counter=True),
        ECA(IntField("packets", None), {AA.R}, counter=True),
        ECA(IntField("broadcast_packets", None), {AA.R}, counter=True),
        ECA(IntField("multicast_packets", None), {AA.R}, counter=True),
        ECA(IntField("crc_errored_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("undersize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("oversize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("64_octets", None), {AA.R}, counter=True),
        ECA(IntField("65_to_127_octets", None), {AA.R}, counter=True),
        ECA(IntField("128_to_255_octets", None), {AA.R}, counter=True),
        ECA(IntField("256_to_511_octets", None), {AA.R}, counter=True),
        ECA(IntField("512_to_1023_octets", None), {AA.R}, counter=True),
        ECA(IntField("1024_to_1518_octets", None), {AA.R}, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    optional_operations = {OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    }


class EthernetFrameExtendedPerformanceMonitoring64Bit(EntityClass):
    class_id = 426
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        # 2-octet field -> Threshold data 1/2 ID
        # 2-octet field -> Parent ME Class
        # 2-octet field -> Parent ME Instance
        # 2-octet field -> Accumulation disable
        # 2-octet field -> TCA Disable
        # 2-octet field -> Control fields bitmap
        # 2-octet field -> TCI
        # 2-octet field -> Reserved
        ECA(FieldListField("control_block", None, ShortField('', 0),
                           count_from=lambda _: 8), {AA.R, AA.W, AA.SBC}),
        ECA(LongField("drop_events", None), {AA.R}, tca=True, counter=True),
        ECA(LongField("octets", None), {AA.R}, counter=True),
        ECA(LongField("packets", None), {AA.R}, counter=True),
        ECA(LongField("broadcast_packets", None), {AA.R}, counter=True),
        ECA(LongField("multicast_packets", None), {AA.R}, counter=True),
        ECA(LongField("crc_errored_packets", None), {AA.R}, tca=True, counter=True),
        ECA(LongField("undersize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(LongField("oversize_packets", None), {AA.R}, tca=True, counter=True),
        ECA(LongField("64_octets", None), {AA.R}, counter=True),
        ECA(LongField("65_to_127_octets", None), {AA.R}, counter=True),
        ECA(LongField("128_to_255_octets", None), {AA.R}, counter=True),
        ECA(LongField("256_to_511_octets", None), {AA.R}, counter=True),
        ECA(LongField("512_to_1023_octets", None), {AA.R}, counter=True),
        ECA(LongField("1024_to_1518_octets", None), {AA.R}, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    optional_operations = {OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        0: 'Drop events',
        1: 'CRC errored packets',
        2: 'Undersize packets',
        3: 'Oversize packets',
    }


class GemPortNetworkCtpMonitoringHistoryData(EntityClass):
    class_id = 341
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("transmitted_gem_frames", None), {AA.R}, counter=True),
        ECA(IntField("received_gem_frames", None), {AA.R}, counter=True),
        ECA(LongField("received_payload_bytes", None), {AA.R}, counter=True),
        ECA(LongField("transmitted_payload_bytes", None), {AA.R}, counter=True),
        ECA(IntField("encryption_key_errors", None), {AA.R}, tca=True, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set, OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        1: 'Encryption key errors',
    }


class XgPonTcPerformanceMonitoringHistoryData(EntityClass):
    class_id = 344
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("psbd_hec_error_count", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("xgtc_hec_error_count", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("unknown_profile_count", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("transmitted_xgem_frames", None), {AA.R}, counter=True),
        ECA(IntField("fragment_xgem_frames", None), {AA.R}, counter=True),
        ECA(IntField("xgem_hec_lost_words_count", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("xgem_key_errors", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("xgem_hec_error_count", None), {AA.R}, tca=True, counter=True)
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    optional_operations = {OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        1: 'PSBd HEC error count',
        2: 'XGTC HEC error count',
        3: 'Unknown profile count',
        4: 'XGEM HEC loss count',
        5: 'XGEM key errors',
        6: 'XGEM HEC error count',
    }


class XgPonDownstreamPerformanceMonitoringHistoryData(EntityClass):
    class_id = 345
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R},),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("ploam_mic_error_count", None), {AA.R}, tca=True, counter=True),
        ECA(IntField("downstream_ploam_messages_count", None), {AA.R}, counter=True),
        ECA(IntField("profile_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("ranging_time_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("deactivate_onu_id_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("disable_serial_number_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("request_registration_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("assign_alloc_id_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("key_control_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("sleep_allow_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("baseline_omci_messages_received_count", None), {AA.R}, counter=True),
        ECA(IntField("extended_omci_messages_received_count", None), {AA.R}, counter=True),
        ECA(IntField("assign_onu_id_messages_received", None), {AA.R}, counter=True),
        ECA(IntField("omci_mic_error_count", None), {AA.R}, tca=True, counter=True),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    optional_operations = {OP.GetCurrentData}
    notifications = {OP.AlarmNotification}
    alarms = {
        1: 'PLOAM MIC error count',
        2: 'OMCI MIC error count',
    }


class XgPonUpstreamPerformanceMonitoringHistoryData(EntityClass):
    class_id = 346
    hidden = True
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("interval_end_time", None), {AA.R}),
        ECA(ShortField("threshold_data_1_2_id", None), {AA.R, AA.W, AA.SBC}),
        ECA(IntField("upstream_ploam_message_count", None), {AA.R}, counter=True),
        ECA(IntField("serial_number_onu_message_count", None), {AA.R}, counter=True),
        ECA(IntField("registration_message_count", None), {AA.R}, counter=True),
        ECA(IntField("key_report_message_count", None), {AA.R}, counter=True),
        ECA(IntField("acknowledge_message_count", None), {AA.R}, counter=True),
        ECA(IntField("sleep_request_message_count", None), {AA.R}, counter=True),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Get, OP.Set}
    optional_operations = {OP.GetCurrentData}


# entity class lookup table from entity_class values
entity_classes_name_map = dict(
    inspect.getmembers(sys.modules[__name__],
    lambda o: inspect.isclass(o) and \
              issubclass(o, EntityClass) and \
              o is not EntityClass)
)

entity_classes = [c for c in entity_classes_name_map.itervalues()]
entity_id_to_class_map = dict((c.class_id, c) for c in entity_classes)
