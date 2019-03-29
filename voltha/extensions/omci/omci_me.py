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
"""
OMCI Managed Entity Frame support
"""
from voltha.extensions.omci.omci import *
from voltha.extensions.omci.me_frame import MEFrame
from voltha.extensions.omci.omci_entities import PriorityQueueG
from voltha.extensions.omci.omci_entities import *



class CardholderFrame(MEFrame):
    """
    This managed entity represents fixed equipment slot configuration
    for the ONU
    """
    def __init__(self, single, slot_number, attributes):
        """
        :param single:(bool) True if the ONU is a single piece of integrated equipment,
                             False if the ONU contains pluggable equipment modules
        :param slot_number: (int) slot number (0..254)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        # Validate
        MEFrame.check_type(single, bool)
        MEFrame.check_type(slot_number, int)
        if not 0 <= slot_number <= 254:
            raise ValueError('slot_number should be 0..254')

        entity_id = 256 + slot_number if single else slot_number

        super(CardholderFrame, self).__init__(Cardholder, entity_id,
                                              MEFrame._attr_to_data(attributes))


class CircuitPackFrame(MEFrame):
    """
    This managed entity models a real or virtual circuit pack that is equipped in
    a real or virtual ONU slot.
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Its value is the same as that
                                of the cardholder managed entity containing this
                                circuit pack instance. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(CircuitPackFrame, self).__init__(CircuitPack, entity_id,
                                               MEFrame._attr_to_data(attributes))


class ExtendedVlanTaggingOperationConfigurationDataFrame(MEFrame):
    """
    This managed entity organizes data associated with VLAN tagging. Regardless
    of its point of attachment, the specified tagging operations refer to the
     upstream direction.
    """
    def __init__(self, entity_id, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Its value is the same as that
                                of the cardholder managed entity containing this
                                circuit pack instance. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(ExtendedVlanTaggingOperationConfigurationDataFrame,
              self).__init__(ExtendedVlanTaggingOperationConfigurationData,
                             entity_id,
                             MEFrame._attr_to_data(attributes))


class IpHostConfigDataFrame(MEFrame):
    """
    The IP host config data configures IPv4 based services offered on the ONU.
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(IpHostConfigDataFrame, self).__init__(IpHostConfigData,
                                                    entity_id,
                                                    MEFrame._attr_to_data(attributes))


class GalEthernetProfileFrame(MEFrame):
    """
    This managed entity organizes data that describe the GTC adaptation layer
    processing functions of the ONU for Ethernet services.
    """
    def __init__(self, entity_id, max_gem_payload_size=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param max_gem_payload_size: (int) This attribute defines the maximum payload
                                     size generated in the associated GEM interworking
                                     termination point managed entity. (0..65535
        """
        MEFrame.check_type(max_gem_payload_size, (int, type(None)))
        if max_gem_payload_size is not None and not 0 <= max_gem_payload_size <= 0xFFFF:  # TODO: verify min/max
            raise ValueError('max_gem_payload_size should be 0..0xFFFF')

        data = None if max_gem_payload_size is None else\
            {
                'max_gem_payload_size': max_gem_payload_size
            }
        super(GalEthernetProfileFrame, self).__init__(GalEthernetProfile,
                                                      entity_id,
                                                      data)


class GemInterworkingTpFrame(MEFrame):
    """
    An instance of this managed entity represents a point in the ONU where the
    interworking of a bearer service (usually Ethernet) to the GEM layer takes
    place.
    """
    def __init__(self, entity_id,
                 gem_port_network_ctp_pointer=None,
                 interworking_option=None,
                 service_profile_pointer=None,
                 interworking_tp_pointer=None,
                 pptp_counter=None,
                 gal_profile_pointer=None,
                 attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param gem_port_network_ctp_pointer: (int) This attribute points to an instance of
                                                 the GEM port network CTP. (0..65535)

        :param interworking_option: (int) This attribute identifies the type
                                of non-GEM function that is being interworked.
                                The options are:
                                    0 Circuit-emulated TDM
                                    1 MAC bridged LAN
                                    2 Reserved
                                    3 Reserved
                                    4 Video return path
                                    5 IEEE 802.1p mapper
                                    6 Downstream broadcast
                                    7 MPLS PW TDM service

        :param service_profile_pointer: (int) This attribute points to an instance of
                                              a service profile.
                            CES service profile                 if interworking option = 0
                            MAC bridge service profile          if interworking option = 1
                            Video return path service profile   if interworking option = 4
                            IEEE 802.1p mapper service profile  if interworking option = 5
                            Null pointer                        if interworking option = 6
                            CES service profile                 if interworking option = 7

        :param interworking_tp_pointer: (int) This attribute is used for the circuit
                                              emulation service and IEEE 802.1p mapper
                                              service without a MAC bridge.

        :param gal_profile_pointer: (int) This attribute points to an instance of
                                              a service profile.

        :param attributes: (basestring, list, set, dict) additional ME attributes.
                           not specifically specified as a parameter. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified..
        """
        # Validate
        self.check_type(gem_port_network_ctp_pointer, (int, type(None)))
        self.check_type(interworking_option, (int, type(None)))
        self.check_type(service_profile_pointer, (int, type(None)))
        self.check_type(interworking_tp_pointer,(int, type(None)))
        self.check_type(pptp_counter,(int, type(None)))
        self.check_type(gal_profile_pointer, (int, type(None)))

        if gem_port_network_ctp_pointer is not None and not 0 <= gem_port_network_ctp_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('gem_port_network_ctp_pointer should be 0..0xFFFE')

        if interworking_option is not None and not 0 <= interworking_option <= 7:
            raise ValueError('interworking_option should be 0..7')

        if service_profile_pointer is not None and not 0 <= service_profile_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('service_profile_pointer should be 0..0xFFFE')

        if interworking_tp_pointer is not None and not 0 <= interworking_tp_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('interworking_tp_pointer should be 0..0xFFFE')

        if pptp_counter is not None and not 0 <= pptp_counter <= 255:  # TODO: Verify max
            raise ValueError('pptp_counter should be 0..255')

        if gal_profile_pointer is not None and not 0 <= gal_profile_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('gal_profile_pointer should be 0..0xFFFE')

        data = MEFrame._attr_to_data(attributes)

        if gem_port_network_ctp_pointer is not None or \
                interworking_option is not None or \
                service_profile_pointer is not None or \
                interworking_tp_pointer is not None or \
                gal_profile_pointer is not None:

            data = data or dict()

            if gem_port_network_ctp_pointer is not None:
                data['gem_port_network_ctp_pointer'] = gem_port_network_ctp_pointer

            if interworking_option is not None:
                data['interworking_option'] = interworking_option

            if service_profile_pointer is not None:
                data['service_profile_pointer'] = service_profile_pointer

            if interworking_tp_pointer is not None:
                data['interworking_tp_pointer'] = interworking_tp_pointer

            if gal_profile_pointer is not None:
                data['gal_profile_pointer'] = gal_profile_pointer

        super(GemInterworkingTpFrame, self).__init__(GemInterworkingTp,
                                                     entity_id,
                                                     data)


class GemPortNetworkCtpFrame(MEFrame):
    """
    This managed entity represents the termination of a GEM port on an ONU.
    """
    def __init__(self, entity_id, port_id=None, tcont_id=None,
                 direction=None, upstream_tm=None, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param port_id: (int) This attribute is the port-ID of the GEM port associated
                              with this CTP

        :param tcont_id: (int) This attribute points to a T-CONT instance

        :param direction: (string) Data direction.  Valid values are:
                                   'upstream'       - UNI-to-ANI
                                   'downstream'     - ANI-to-UNI
                                   'bi-directional' - guess :-)

        :param upstream_tm: (int) If the traffic management option attribute in
                                  the ONU-G ME is 0 (priority controlled) or 2
                                  (priority and rate controlled), this pointer
                                  specifies the priority queue ME serving this GEM
                                  port network CTP. If the traffic management
                                  option attribute is 1 (rate controlled), this
                                  attribute redundantly points to the T-CONT serving
                                  this GEM port network CTP.

        :param attributes: (basestring, list, set, dict) additional ME attributes.
                           not specifically specified as a parameter. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        _directions = {"upstream": 1, "downstream": 2, "bi-directional": 3}

        # Validate
        self.check_type(port_id, (int, type(None)))
        self.check_type(tcont_id, (int, type(None)))
        self.check_type(direction, (basestring, type(None)))
        self.check_type(upstream_tm, (int, type(None)))

        if port_id is not None and not 0 <= port_id <= 0xFFFE:  # TODO: Verify max
            raise ValueError('port_id should be 0..0xFFFE')

        if tcont_id is not None and not 0 <= tcont_id <= 0xFFFE:  # TODO: Verify max
            raise ValueError('tcont_id should be 0..0xFFFE')

        if direction is not None and str(direction).lower() not in _directions:
            raise ValueError('direction should one of {}'.format(_directions.keys()))

        if upstream_tm is not None and not 0 <= upstream_tm <= 0xFFFE:  # TODO: Verify max
            raise ValueError('upstream_tm should be 0..0xFFFE')

        data = MEFrame._attr_to_data(attributes)

        if port_id is not None or tcont_id is not None or\
                direction is not None or upstream_tm is not None:

            data = data or dict()

            if port_id is not None:
                data['port_id'] = port_id
            if tcont_id is not None:
                data['tcont_pointer'] = tcont_id
            if direction is not None:
                data['direction'] = _directions[str(direction).lower()]
            if upstream_tm is not None:
                data['traffic_management_pointer_upstream'] = upstream_tm

        super(GemPortNetworkCtpFrame, self).__init__(GemPortNetworkCtp,
                                                     entity_id,
                                                     data)


class Ieee8021pMapperServiceProfileFrame(MEFrame):
    """
    This managed entity associates the priorities of IEEE 802.1p [IEEE
    802.1D] priority tagged frames with specific connections.
    """
    def __init__(self, entity_id, tp_pointer=None, interwork_tp_pointers=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param tp_pointer: (int) This attribute points to an instance of the
                                 associated termination point. (0..65535)

        :param interwork_tp_pointers: (list) List of 1 to 8 interworking termination
                                   point IDs. The first entry is assigned
                                   got p-bit priority 0. If less than 8 IDs
                                   are provided, the last ID is used for
                                   the remaining items.
        """
        if tp_pointer is None and interwork_tp_pointers is None:
            data = dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_1=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_2=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_3=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_4=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_5=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_6=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_7=OmciNullPointer
                )
        else:
            self.check_type(tp_pointer, (list, type(None)))
            self.check_type(interwork_tp_pointers, (list, type(None)))

            data = dict()

            if tp_pointer is not None:
                data['tp_pointer'] = tp_pointer

            if interwork_tp_pointers is not None:
                assert all(isinstance(tp, int) and 0 <= tp <= 0xFFFF
                           for tp in interwork_tp_pointers),\
                    'Interworking TP IDs must be 0..0xFFFF'
                assert 1 <= len(interwork_tp_pointers) <= 8, \
                    'Invalid number of Interworking TP IDs. Must be 1..8'

                data = dict()
                for pbit in range(0, len(interwork_tp_pointers)):
                    data['interwork_tp_pointer_for_p_bit_priority_{}'.format(pbit)] = \
                        interwork_tp_pointers[pbit]

                for pbit in range(len(interwork_tp_pointers), 8):
                    data['interwork_tp_pointer_for_p_bit_priority_{}'.format(pbit)] = \
                        interwork_tp_pointers[len(interwork_tp_pointers) - 1]

        super(Ieee8021pMapperServiceProfileFrame, self).__init__(Ieee8021pMapperServiceProfile,
                                                                 entity_id,
                                                                 data)


class MacBridgePortConfigurationDataFrame(MEFrame):
    """
    This managed entity represents the ONU as equipment.
    """
    def __init__(self, entity_id, bridge_id_pointer=None, port_num=None,
                 tp_type=None, tp_pointer=None, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param bridge_id_pointer: (int) This attribute points to an instance of the
                                        MAC bridge service profile. (0..65535)

        :param port_num: (int) This attribute is the bridge port number. (0..255)

        :param tp_type: (int) This attribute identifies the type of termination point
                              associated with this MAC bridge port. Valid values are:
                        1  Physical path termination point Ethernet UNI
                        2  Interworking VCC termination point
                        3  IEEE 802.1p mapper service profile
                        4  IP host config data or IPv6 host config data
                        5  GEM interworking termination point
                        6  Multicast GEM interworking termination point
                        7  Physical path termination point xDSL UNI part 1
                        8  Physical path termination point VDSL UNI
                        9  Ethernet flow termination point
                        10 Reserved
                        11 Virtual Ethernet interface point
                        12 Physical path termination point MoCA UNI

        :param tp_pointer: (int) This attribute points to the termination point
                                 associated with this MAC bridge por. (0..65535)

        :param attributes: (basestring, list, set, dict) additional ME attributes.
                           not specifically specified as a parameter. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        # Validate
        self.check_type(bridge_id_pointer, (int, type(None)))
        self.check_type(port_num, (int, type(None)))
        self.check_type(tp_type, (int, type(None)))
        self.check_type(tp_pointer, (int, type(None)))

        if bridge_id_pointer is not None and not 0 <= bridge_id_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('bridge_id_pointer should be 0..0xFFFE')

        if port_num is not None and not 0 <= port_num <= 255:
            raise ValueError('port_num should be 0..255')       # TODO: Verify min,max

        if tp_type is not None and not 1 <= tp_type <= 12:
            raise ValueError('service_profile_pointer should be 1..12')

        if tp_pointer is not None and not 0 <= tp_pointer <= 0xFFFE:  # TODO: Verify max
            raise ValueError('interworking_tp_pointer should be 0..0xFFFE')

        data = MEFrame._attr_to_data(attributes)

        if bridge_id_pointer is not None or \
                port_num is not None or \
                tp_type is not None or \
                tp_pointer is not None:

            data = data or dict()

            if bridge_id_pointer is not None:
                data['bridge_id_pointer'] = bridge_id_pointer

            if port_num is not None:
                data['port_num'] = port_num

            if tp_type is not None:
                data['tp_type'] = tp_type

            if tp_pointer is not None:
                data['tp_pointer'] = tp_pointer

        super(MacBridgePortConfigurationDataFrame, self).\
            __init__(MacBridgePortConfigurationData, entity_id, data)


class MacBridgeServiceProfileFrame(MEFrame):
    """
    This managed entity models a MAC bridge in its entirety; any number
    of ports may be associated with the bridge through pointers to the
    MAC bridge service profile managed entity.
    """
    def __init__(self, entity_id, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(MacBridgeServiceProfileFrame, self).__init__(MacBridgeServiceProfile,
                                                           entity_id,
                                                           MEFrame._attr_to_data(attributes))


class OntGFrame(MEFrame):
    """
    This managed entity represents the ONU as equipment.
    """
    def __init__(self, attributes=None):
        """
        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(OntGFrame, self).__init__(OntG, 0,
                                        MEFrame._attr_to_data(attributes))


class Ont2GFrame(MEFrame):
    """
    This managed entity contains additional attributes associated with a PON ONU.
    """
    def __init__(self, attributes=None):
        """
        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        # Only one managed entity instance (Entity ID=0)
        super(Ont2GFrame, self).__init__(Ont2G, 0,
                                         MEFrame._attr_to_data(attributes))


class PptpEthernetUniFrame(MEFrame):
    """
    This managed entity represents the point at an Ethernet UNI where the physical path
    terminates and Ethernet physical level functions are performed.
    """
    def __init__(self, entity_id, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(PptpEthernetUniFrame, self).__init__(PptpEthernetUni, entity_id,
                                                   MEFrame._attr_to_data(attributes))


class VeipUniFrame(MEFrame):
    """
    This managed entity represents the point a virtual UNI interfaces to a non omci management domain
    This is typically seen in RG+ONU all-in-one type devices
    """
    def __init__(self, entity_id, attributes=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For create/set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(VeipUniFrame, self).__init__(VeipUni, entity_id,
                                           MEFrame._attr_to_data(attributes))


class SoftwareImageFrame(MEFrame):
    """
    This managed entity models an executable software image stored in the ONU.
    """
    def __init__(self, entity_id):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)
        """
        super(SoftwareImageFrame, self).__init__(SoftwareImage, entity_id, None)


class TcontFrame(MEFrame):
    """
    An instance of the traffic container managed entity T-CONT represents a
    logical connection group associated with a G-PON PLOAM layer alloc-ID.
    """
    def __init__(self, entity_id, alloc_id=None, policy=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param alloc_id: (int) This attribute links the T-CONT with the alloc-ID
                               assigned by the OLT in the assign_alloc-ID PLOAM
                               message (0..0xFFF) or 0xFFFF to mark as free

        :param policy: (int) This attribute indicates the T-CONT's traffic scheduling
                             policy. Valid values:
                                0 - Null
                                1 - Strict priority
                                2 - WRR - Weighted round robin
        """
        # Validate
        self.check_type(alloc_id, (int, type(None)))
        self.check_type(policy, (int, type(None)))

        if alloc_id is not None and not (0 <= alloc_id <= 0xFFF or alloc_id == 0xFFFF):
            raise ValueError('alloc_id should be 0..0xFFF or 0xFFFF to mark it as free')

        if policy is not None and not 0 <= policy <= 2:
            raise ValueError('policy should be 0..2')

        if alloc_id is None and policy is None:
            data = None
        else:
            data = dict()

            if alloc_id is not None:
                data['alloc_id'] = alloc_id

            if policy is not None:
                data['policy'] = policy

        super(TcontFrame, self).__init__(Tcont, entity_id, data)


class VlanTaggingFilterDataFrame(MEFrame):
    """
    An instance of this managed entity represents a point in the ONU where the
    interworking of a bearer service (usually Ethernet) to the GEM layer takes
    place.
    """
    def __init__(self, entity_id, vlan_tcis=None, forward_operation=None):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. (0..65535)

        :param vlan_tcis: (list) This attribute is a list of provisioned TCI values
                                 for the bridge port. (0..0xFFFF)

        :param forward_operation: (int) What to do.  See ITU spec for more information

        """
        # Validate
        self.check_type(vlan_tcis, (list, type(None)))
        self.check_type(forward_operation, (int, type(None)))

        if forward_operation is not None and not 0 <= forward_operation <= 0x21:
            raise ValueError('forward_operation should be 0..0x21')

        if vlan_tcis is None and forward_operation is None:
            data = None

        else:
            data = dict()

            if vlan_tcis is not None:
                num_tcis = len(vlan_tcis)

                assert 0 <= num_tcis <= 12, 'Number of VLAN TCI values is 0..12'
                assert all(isinstance(tci, int) and 0 <= tci <= 0xFFFF
                           for tci in vlan_tcis), "VLAN TCI's are 0..0xFFFF"

                if num_tcis > 0:
                    vlan_filter_list = [0] * 12
                    for index in range(0, num_tcis):
                        vlan_filter_list[index] = vlan_tcis[index]

                    data['vlan_filter_list'] = vlan_filter_list
                data['number_of_entries'] = num_tcis

            if forward_operation is not None:
                assert 0 <= forward_operation <= 0x21, \
                    'forwarding_operation must be 0x00..0x21'
                data['forward_operation'] = forward_operation

        super(VlanTaggingFilterDataFrame, self).__init__(VlanTaggingFilterData,
                                                         entity_id,
                                                         data)


class OntDataFrame(MEFrame):
    """
    This managed entity models the MIB itself
    """
    def __init__(self, mib_data_sync=None, sequence_number=None, ignore_arc=None):
        """
        For 'get', 'MIB reset', 'MIB upload', pass no value
        For 'set' actions, pass mib_data_sync value (0..255)
        For 'MIB upload next',and 'Get all alarms next' pass sequence_number value (0..65535)
        For 'Get all alarms", set ignore_arc to True to get all alarms regadrless
                              of ARC status or False to get all alarms not currently
                              under ARC

        :param mib_data_sync: (int) This attribute is used to check the alignment
                                    of the MIB of the ONU with the corresponding MIB
                                    in the OLT. (0..0xFF)
        :param sequence_number: (int) This is used for MIB Upload Next (0..0xFFFF)
        :param ignore_arc: (bool) None for all but 'get_all_alarm' commands
        """
        self.check_type(mib_data_sync, (int, type(None)))
        if mib_data_sync is not None and not 0 <= mib_data_sync <= 0xFF:
            raise ValueError('mib_data_sync should be 0..0xFF')

        if sequence_number is not None and not 0 <= sequence_number <= 0xFFFF:
            raise ValueError('sequence_number should be 0..0xFFFF')

        if ignore_arc is not None and not isinstance(ignore_arc, bool):
            raise TypeError('ignore_arc should be a boolean')

        if mib_data_sync is not None:
            # Note: Currently the Scapy decode/encode is 16-bits since we need
            #       the data field that large in order to support MIB and Alarm Upload Next
            #       commands.  Push our 8-bit MDS value into the upper 8-bits so that
            #       it is encoded properly into the ONT_Data 'set' frame
            data = {'mib_data_sync': mib_data_sync << 8}

        elif sequence_number is not None:
            data = {'mib_data_sync': sequence_number}

        elif ignore_arc is not None:
            data = {'mib_data_sync': 0 if ignore_arc else 1}

        else:
            data = {'mib_data_sync'}    # Make Get's happy

        super(OntDataFrame, self).__init__(OntData, 0, data)


class OmciFrame(MEFrame):
    """
    This managed entity describes the ONU's general level of support for OMCI managed
    entities and messages. This ME is not included in a MIB upload.
    """
    def __init__(self, me_type_table=None, message_type_table=None):
        """
        For 'get' request, set the type of table count you wish by
        setting either me_me_type_table or message_type_table to
        a boolean 'True' value

        For 'get-next' requests, set the sequence number for the
        table you wish to retrieve by setting either me_me_type_table or message_type_table to
        a integer value.
        """
        if not isinstance(me_type_table, (bool, int, type(None))):
            raise TypeError('Parameters must be a boolean or integer')

        if not isinstance(message_type_table, (bool, int, type(None))):
            raise TypeError('Parameters must be a boolean or integer')

        if me_type_table is not None:
            if isinstance(me_type_table, bool):
                data = {'me_type_table'}
            else:
                data = {'me_type_table': me_type_table}

        elif message_type_table is not None:
            if isinstance('message_type_table', bool):
                data = {'message_type_table'}
            else:
                data = {'message_type_table': message_type_table}
        else:
            raise NotImplemented('Unknown request')

        super(OmciFrame, self).__init__(Omci, 0, data)


class EthernetPMMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects some of the performance monitoring data for a physical
    Ethernet interface
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                 managed entity is implicitly linked to an instance
                                 of the physical path termination point Ethernet UNI

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(EthernetPMMonitoringHistoryDataFrame, self).__init__(
            EthernetPMMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class FecPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with PON
    downstream FEC counters.
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                the ANI-G

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(FecPerformanceMonitoringHistoryDataFrame, self).__init__(
            FecPerformanceMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class EthernetFrameDownstreamPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with downstream
    Ethernet frame delivery. It is based on the Etherstats group of [IETF RFC 2819].
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                a MAC bridge port configuration data

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(EthernetFrameDownstreamPerformanceMonitoringHistoryDataFrame, self).__init__(
            EthernetFrameDownstreamPerformanceMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class EthernetFrameUpstreamPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with upstream
    Ethernet frame delivery. It is based on the Etherstats group of [IETF RFC 2819].
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                a MAC bridge port configuration data

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(EthernetFrameUpstreamPerformanceMonitoringHistoryDataFrame, self).__init__(
            EthernetFrameUpstreamPerformanceMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class GemPortNetworkCtpMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects GEM frame performance monitoring data associated
    with a GEM port network CTP
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance
                                of the GEM port network CTP.

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(GemPortNetworkCtpMonitoringHistoryDataFrame, self).__init__(
            GemPortNetworkCtpMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class XgPonTcPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with
    the XG-PON transmission convergence layer, as defined in [ITU-T G.987.3]
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                the ANI-G.

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(XgPonTcPerformanceMonitoringHistoryDataFrame, self).__init__(
            XgPonTcPerformanceMonitoringHistoryData, entity_id,
            MEFrame._attr_to_data(attributes))


class XgPonDownstreamPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with
    the XG-PON ined in [ITU-T G.987.3]
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) This attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                the ANI-G.

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(XgPonDownstreamPerformanceMonitoringHistoryDataFrame, self).__init__(
            XgPonDownstreamPerformanceMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class XgPonUpstreamPerformanceMonitoringHistoryDataFrame(MEFrame):
    """
    This managed entity collects performance monitoring data associated with
    the XG-PON transmission convergence layer, as defined in [ITU-T G.987.3]
    """
    def __init__(self, entity_id, attributes):
        """
        :param entity_id: (int) TThis attribute uniquely identifies each instance of
                                this managed entity. Through an identical ID, this
                                managed entity is implicitly linked to an instance of
                                the ANI-G.

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, or set can be provided. For set
                           operations, a dictionary should be provided, for
                           deletes None may be specified.
        """
        super(XgPonUpstreamPerformanceMonitoringHistoryDataFrame, self).__init__(
            XgPonUpstreamPerformanceMonitoringHistoryData,
            entity_id,
            MEFrame._attr_to_data(attributes))


class PriorityQueueFrame(MEFrame):
    def __init__(self, entity_id, related_port=None, traffic_scheduler_pointer=None, weight=None):

        self.check_type(entity_id, (int, type(None)))
        self.check_type(related_port, (int, type(None)))
        self.check_type(traffic_scheduler_pointer, (int, type(None)))
        self.check_type(weight, (int, type(None)))

        assert entity_id is not None, "WARNING: Entity_ID not present"
        data = dict()
        if related_port is not None:
            data['related_port'] = related_port
        if traffic_scheduler_pointer is not None:
            data['traffic_scheduler_pointer'] = traffic_scheduler_pointer
        if weight is not None:
            data['weight'] = weight

        super(PriorityQueueFrame, self).__init__(PriorityQueueG, entity_id, data)
