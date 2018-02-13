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
from scapy.fields import ByteField, ShortField
from scapy.fields import IntField, StrFixedLenField


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
    ]
    mandatory_operations = {OP.Get}


class VerizonOpenOMCI(EntityClass):
    class_id = 65400
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Get}


class TwdmSystemProfile(EntityClass):
    class_id = 65401
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Get}


class TwdmChannel(EntityClass):
    class_id = 65402
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Get}


class WatchdogConfigData(EntityClass):
    class_id = 65403
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Get}


class FCPortalOrSraStat(EntityClass):
    class_id = 65420
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Create, OP.Delete}


class Onu3gOrInvStat2(EntityClass):
    class_id = 65422
    attributes = [
        ECA(ShortField("managed_entity_id", None), {AA.R, AA.SBC}),
    ]
    mandatory_operations = {OP.Set, OP.Get, OP.Create, OP.Delete}


#################################################################################
# entity class lookup table from entity_class values
_onu_entity_classes_name_map = dict(
    inspect.getmembers(sys.modules[__name__],
    lambda o: inspect.isclass(o) and
              issubclass(o, EntityClass) and
              o is not EntityClass)
)

onu_custom_entity_classes = [c for c in _onu_entity_classes_name_map.itervalues()]


def add_onu_me_entities(new_me_classes):
    from voltha.extensions.omci.omci_entities import entity_classes, entity_id_to_class_map

    for entity_class in new_me_classes:
        assert entity_class.class_id not in entity_id_to_class_map, \
            "Class ID '{}' already exists in the class map".format(entity_class.class_id)
        entity_id_to_class_map[entity_class.class_id] = entity_class

    entity_classes.extend(new_me_classes)
