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
from scapy.fields import ShortField, IntField, ByteField, StrFixedLenField
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

