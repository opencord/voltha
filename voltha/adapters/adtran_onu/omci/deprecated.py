# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from voltha.extensions.omci.omci import *


DEFAULT_OMCI_TIMEOUT = 3            # Seconds

# TODO: These are the older-style OMCI commands to send get/create/... frames


def send_get_OntG(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_OntG')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=OntG.class_id,
            entity_id=entity_id,
            attributes_mask=OntG.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_vlan_tagging_filter_data(omci_cc, entity_id, vlan_id,
                                         timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=VlanTaggingFilterData.class_id,
            entity_id=entity_id,
            data=dict(
                vlan_filter_0=vlan_id,
                forward_operation=0x10,
                number_of_entries=1
            )
        )
    )
    return omci_cc.send(frame, timeout)

# TODO: Deprecated: replaced with send_set_pptp_ethernet_uni  (need to clean up)


def send_set_adminState(omci_cc, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_set_AdminState')
    data = dict(
        administrative_state=0
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=PptpEthernetUni.class_id,
            entity_id=entity_id,
            attributes_mask=PptpEthernetUni.mask_for(*data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_SoftwareImage(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_SoftwareImage')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=SoftwareImage.class_id,
            entity_id=entity_id,
            attributes_mask=SoftwareImage.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(omci_cc,
                                                                              entity_id,
                                                                              filter_inner_vid,
                                                                              treatment_inner_vid,
                                                                              timeout=DEFAULT_OMCI_TIMEOUT):
    data = dict(
        received_frame_vlan_tagging_operation_table=
        VlanTaggingOperation(
            filter_outer_priority=15,
            filter_outer_vid=4096,
            filter_outer_tpid_de=0,

            filter_inner_priority=15,
            filter_inner_vid=filter_inner_vid,
            filter_inner_tpid_de=0,
            filter_ether_type=0,

            treatment_tags_to_remove=0,
            treatment_outer_priority=15,
            treatment_outer_vid=0,
            treatment_outer_tpid_de=0,

            treatment_inner_priority=0,
            treatment_inner_vid=treatment_inner_vid,
            treatment_inner_tpid_de=4
        )
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=
            ExtendedVlanTaggingOperationConfigurationData.class_id,
            entity_id=entity_id,
            attributes_mask=
            ExtendedVlanTaggingOperationConfigurationData.mask_for(
                *data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(omci_cc,
                                                                                entity_id,
                                                                                filter_inner_priority,
                                                                                filter_inner_vid,
                                                                                filter_inner_tpid_de,
                                                                                treatment_tags_to_remove,
                                                                                treatment_inner_priority,
                                                                                treatment_inner_vid,
                                                                                timeout=DEFAULT_OMCI_TIMEOUT):
    data = dict(
        received_frame_vlan_tagging_operation_table=
        VlanTaggingOperation(
            filter_outer_priority=15,
            filter_outer_vid=4096,
            filter_outer_tpid_de=0,
            filter_inner_priority=filter_inner_priority,
            filter_inner_vid=filter_inner_vid,
            filter_inner_tpid_de=filter_inner_tpid_de,
            filter_ether_type=0,
            treatment_tags_to_remove=treatment_tags_to_remove,
            treatment_outer_priority=15,
            treatment_outer_vid=0,
            treatment_outer_tpid_de=0,
            treatment_inner_priority=treatment_inner_priority,
            treatment_inner_vid=treatment_inner_vid,
            treatment_inner_tpid_de=4
        )
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=
            ExtendedVlanTaggingOperationConfigurationData.class_id,
            entity_id=entity_id,
            attributes_mask=
            ExtendedVlanTaggingOperationConfigurationData.mask_for(
                *data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_delete_vlan_tagging_filter_data(omci_cc,
                                      entity_id):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciDelete.message_id,
        omci_message=OmciDelete(
            entity_class=VlanTaggingFilterData.class_id,
            entity_id=entity_id
        )
    )
    return omci_cc.send(frame)

# xxxxxxxxxxxxxxxxxxxxxxxxxxxxx


def send_set_tcont(omci_cc, entity_id, alloc_id, timeout=DEFAULT_OMCI_TIMEOUT):
    data = dict(
        alloc_id=alloc_id
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=Tcont.class_id,
            entity_id=entity_id,
            attributes_mask=Tcont.mask_for(*data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_gem_port_network_ctp(omci_cc, entity_id, port_id,
                                     tcont_id, direction, tm,
                                     timeout=DEFAULT_OMCI_TIMEOUT):

    _directions = {"upstream": 1, "downstream": 2, "bi-directional": 3}

    if _directions.has_key(direction):
        _direction = _directions[direction]
    else:
        omci_cc.log.error('invalid-gem-port-direction', direction=direction)
        raise ValueError('Invalid GEM port direction: {_dir}'.format(_dir=direction))

    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=GemPortNetworkCtp.class_id,
            entity_id=entity_id,
            data=dict(
                port_id=port_id,
                tcont_pointer=tcont_id,
                direction=_direction,
                traffic_management_pointer_upstream=tm
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_set_8021p_mapper_service_profile(omci_cc, entity_id,
                                          interwork_tp_id,
                                          timeout=DEFAULT_OMCI_TIMEOUT):
    data = dict(
        interwork_tp_pointer_for_p_bit_priority_0=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_1=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_2=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_3=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_4=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_5=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_6=interwork_tp_id,
        interwork_tp_pointer_for_p_bit_priority_7=interwork_tp_id
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=Ieee8021pMapperServiceProfile.class_id,
            entity_id=entity_id,
            attributes_mask=Ieee8021pMapperServiceProfile.mask_for(
                *data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_8021p_mapper_service_profile(omci_cc, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=Ieee8021pMapperServiceProfile.class_id,
            entity_id=entity_id,
            data=dict(
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
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_mac_bridge_service_profile(omci_cc, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=MacBridgeServiceProfile.class_id,
            entity_id=entity_id,
            data=dict(
                spanning_tree_ind=False,
                # BP: Hack , this was not set in ADT configuration
                # learning_ind=True,
                # priority=0x8000,
                # max_age=20 * 256,
                # hello_time=2 * 256,
                # forward_delay=15 * 256,
                # unknown_mac_address_discard=True
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_gal_ethernet_profile(omci_cc, entity_id, max_gem_payload_size,
                                     timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=GalEthernetProfile.class_id,
            entity_id=entity_id,
            data=dict(
                max_gem_payload_size=max_gem_payload_size
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_gem_inteworking_tp(omci_cc, entity_id, gem_port_net_ctp_id,
                                   service_profile_id, timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=GemInterworkingTp.class_id,
            entity_id=entity_id,
            data=dict(
                gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                interworking_option=5,
                service_profile_pointer=service_profile_id,
                interworking_tp_pointer=0x0,
                pptp_counter=1,
                gal_profile_pointer=0x0   # BP: HACK old value 0x1
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_mac_bridge_port_configuration_data(omci_cc, entity_id, bridge_id,
                                                   port_id, tp_type, tp_id,
                                                   timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=MacBridgePortConfigurationData.class_id,
            entity_id=entity_id,
            data=dict(
                bridge_id_pointer=bridge_id,
                port_num=port_id,
                tp_type=tp_type,
                tp_pointer=tp_id
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_circuit_pack(omci_cc, attribute, entity_id=0,
                          timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_circuit_pack')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=CircuitPack.class_id,
            entity_id=entity_id,
            attributes_mask=CircuitPack.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_device_info(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=CircuitPack.class_id,
            entity_id=entity_id,
            attributes_mask=CircuitPack.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_Ont2G(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_Ont2G')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=Ont2G.class_id,
            entity_id=entity_id,
            attributes_mask=Ont2G.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_cardHolder(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_cardHolder')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=Cardholder.class_id,
            entity_id=entity_id,
            attributes_mask=Cardholder.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_set_pptp_ethernet_uni(omci_cc, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_set_AdminState')
    data = dict(
        administrative_state=0
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=PptpEthernetUni.class_id,
            entity_id=entity_id,
            attributes_mask=PptpEthernetUni.mask_for(*data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)


def send_get_IpHostConfigData(omci_cc, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    omci_cc.log.debug('send_get_IpHostConfigData')
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciGet.message_id,
        omci_message=OmciGet(
            entity_class=IpHostConfigData.class_id,
            entity_id=entity_id,
            attributes_mask=IpHostConfigData.mask_for(attribute)
        )
    )
    return omci_cc.send(frame, timeout)


def send_create_extended_vlan_tagging_operation_configuration_data(omci_cc,
                                                                   entity_id,
                                                                   assoc_type,
                                                                   assoc_me,
                                                                   timeout=DEFAULT_OMCI_TIMEOUT):
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciCreate.message_id,
        omci_message=OmciCreate(
            entity_class=
            ExtendedVlanTaggingOperationConfigurationData.class_id,
            entity_id=entity_id,
            data=dict(
                association_type=assoc_type,
                associated_me_pointer=assoc_me
            )
        )
    )
    return omci_cc.send(frame, timeout)


def send_set_extended_vlan_tagging_operation_tpid_configuration_data(omci_cc,
                                                                     entity_id,
                                                                     input_tpid,
                                                                     output_tpid,
                                                                     timeout=DEFAULT_OMCI_TIMEOUT):
    data = dict(
        input_tpid=input_tpid,
        output_tpid=output_tpid,
        downstream_mode=0,  # inverse of upstream
    )
    frame = OmciFrame(
        transaction_id=omci_cc._get_tx_tid(),
        message_type=OmciSet.message_id,
        omci_message=OmciSet(
            entity_class=
            ExtendedVlanTaggingOperationConfigurationData.class_id,
            entity_id=entity_id,
            attributes_mask=
            ExtendedVlanTaggingOperationConfigurationData.mask_for(
                *data.keys()),
            data=data
        )
    )
    return omci_cc.send(frame, timeout)
