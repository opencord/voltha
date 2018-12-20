# Copyright 2017-present Adtran, Inc.
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
""" Adtran vendor-specific OMCI Entities"""

import inspect
import sys
import json
from binascii import hexlify
from bitstring import BitArray
from scapy.fields import ByteField, ShortField,  BitField
from scapy.fields import IntField, StrFixedLenField, FieldListField, PacketLenField
from scapy.packet import Packet
from voltha.extensions.omci.omci_entities import EntityClassAttribute, \
    AttributeAccess, EntityOperations, EntityClass

# abbreviations
ECA = EntityClassAttribute
AA = AttributeAccess
OP = EntityOperations


class OntSystem(EntityClass):
    class_id = 65300
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(StrFixedLenField("time_of_day", None, 8), {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Get}


class VerizonOpenOMCI(EntityClass):
    class_id = 65400
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(IntField("supported_specification_version", None), {AA.R}),
        ECA(ShortField("pon_device_type", None), {AA.R}),
        ECA(IntField("specification_in_use", None), {AA.R, AA.W})
    ]
    mandatory_operations = {OP.Get, OP.Set}


class TwdmSystemProfile(EntityClass):
    class_id = 65401
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("total_twdm_channel_number", None), {AA.R}),
        ECA(ByteField("channel_partition_index", None), {AA.R, AA.W}),
        ECA(IntField("channel_partion_waiver_timer", None), {AA.R, AA.W}),
        ECA(IntField("lods_re_initialization_timer", None), {AA.R, AA.W}),
        ECA(IntField("lods_protection_timer", None), {AA.R, AA.W}),
        ECA(IntField("downstream_tuning_timer", None), {AA.R, AA.W}),
        ECA(IntField("upstream_tuning_timer", None), {AA.R, AA.W}),
        ECA(StrFixedLenField("location_label_1", None, 24), {AA.R, AA.W}),
        ECA(StrFixedLenField("location_label_2", None, 24), {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Get, OP.Set}


class TwdmChannel(EntityClass):
    class_id = 65402
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("active_channel_indication", None), {AA.R}),
        ECA(ByteField("operational_channel_indication", None), {AA.R}),
        ECA(ByteField("downstream_wavelength_channel", None), {AA.R}),
        ECA(ByteField("upstream_wavelength_channel", None), {AA.R}),
    ]
    mandatory_operations = {OP.Get}


class WatchdogConfigData(EntityClass):
    class_id = 65403
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(IntField("upstream_transmission_timing_drift_self_monitoring_capability", None), {AA.R}),
        ECA(IntField("upstream_transmission_wavelength_drift_self_monitoring_capability", None), {AA.R}),
        ECA(IntField("upstream_transmission_optical_power_self_monitoring_capability", None), {AA.R}),
        ECA(IntField("mean_out_of_channel_optical_power_spectral_density_self_monitoring_capability", None), {AA.R}),
        ECA(IntField("mean_optical_power_spectral_density_self_monitoring_capability", None), {AA.R}),
    ]
    mandatory_operations = {OP.Get}


class FlexibleConfigurationStatusPortal(EntityClass):
    class_id = 65420
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(IntField("service_instance", None), {AA.R, AA.W}),
        ECA(ShortField("configuration_method", None), {AA.R, AA.W}),
        ECA(ShortField("network_address", None), {AA.R, AA.W}),
        ECA(ByteField("administrative_state", None), {AA.R, AA}),
        ECA(ByteField("operational_state", None), {AA.R}, avc=True),
        ECA(ShortField("cause_for_last_abnormal_halt", None), {AA.R}),
        ECA(ShortField("configuration_portal_update_available", None), {AA.R, AA.W}),
        ECA(StrFixedLenField("configuration_portal_table", None, 25), {AA.R, AA.W}),
        ECA(ByteField("configuration_portal_result", None), {AA.R, AA.W}, avc=True),
        ECA(ShortField("status_message_available", None), {AA.R, AA.W}, avc=True),
        ECA(ByteField("status_message", None), {AA.R, AA.W}),
        ECA(ByteField("status_message_result", None), {AA.R, AA.W}),
        ECA(ShortField("associated_me_class", None), {AA.R}),
        ECA(ShortField("associated_me_class_instance", None), {AA.R}),
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Create, OP.Delete, OP.GetNext, OP.SetTable}


class Onu3G(EntityClass):
    class_id = 65422
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
        ECA(ByteField("flash_memory_performance_value", None), {AA.R}),
        ECA(ByteField("latest_restart_reason", None), {AA.R}),
        ECA(ShortField("total_number_of_status_snapshots", None), {AA.R}),
        ECA(ShortField("number_of_valid_status_snapshots", None), {AA.R}),
        ECA(ShortField("next_status_snapshot_index", None), {AA.R}),
        ECA(ByteField("status_snapshot_record_table", None), {AA.R}),      # TODO: MxN field
        ECA(ByteField("snap_action", None), {AA.W}),
        ECA(ByteField("most_recent_status_snapshot", None), {AA.R}),        # TODO: N field
        ECA(ByteField("reset_action", None), {AA.W}),
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.GetNext}


class AdtnVlanTaggingOperation(Packet):
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
        temp = AdtnVlanTaggingOperation(
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


class AdtnExtendedVlanTaggingOperationConfigurationData(EntityClass):
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
        ECA(StrFixedLenField("received_frame_vlan_tagging_operation_table",
                             AdtnVlanTaggingOperation, 16), {AA.R, AA.W}),
        ECA(ShortField("associated_me_pointer", None), {AA.R, AA.W, AA.SBC}),
        ECA(FieldListField("dscp_to_p_bit_mapping", None,
                           BitField('',  0, size=3), count_from=lambda _: 64),
            {AA.R, AA.W}),
    ]
    mandatory_operations = {OP.Create, OP.Delete, OP.Set, OP.Get, OP.GetNext}
    optional_operations = {OP.SetTable}




#################################################################################
# entity class lookup table from entity_class values
_onu_entity_classes_name_map = dict(
    inspect.getmembers(sys.modules[__name__], lambda o:
    inspect.isclass(o) and issubclass(o, EntityClass) and o is not EntityClass)
)
_onu_custom_entity_classes = [c for c in _onu_entity_classes_name_map.itervalues()]
_onu_custom_entity_id_to_class_map = dict()


def onu_custom_me_entities():
    if len(_onu_custom_entity_id_to_class_map) == 0:
        for entity_class in _onu_custom_entity_classes:
            assert entity_class.class_id not in _onu_custom_entity_id_to_class_map, \
                "Class ID '{}' already exists in the class map".format(entity_class.class_id)
            _onu_custom_entity_id_to_class_map[entity_class.class_id] = entity_class

    return _onu_custom_entity_id_to_class_map

