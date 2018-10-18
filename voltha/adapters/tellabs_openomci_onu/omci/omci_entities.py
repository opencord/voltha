# Copyright 2018-present Tellabs, Inc.
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
""" Tellabs vendor-specific OMCI Entities"""

import inspect
import structlog
import sys

from scapy.fields import ShortField, IntField, ByteField, StrFixedLenField
from voltha.extensions.omci.omci_entities import EntityClassAttribute, \
    AttributeAccess, OmciNullPointer, EntityOperations, EntityClass

log = structlog.get_logger()

# abbreviations
ECA = EntityClassAttribute
AA = AttributeAccess
OP = EntityOperations

#################################################################################
# entity class lookup table from entity_class values
_onu_entity_classes_name_map = dict(
    inspect.getmembers(sys.modules[__name__], lambda o:
    inspect.isclass(o) and issubclass(o, EntityClass) and o is not EntityClass)
)
_onu_custom_entity_classes = [c for c in _onu_entity_classes_name_map.itervalues()]
_onu_custom_entity_id_to_class_map = dict()


def onu_custom_me_entities():
    log.info('onu_custom_me_entities')

    if len(_onu_custom_entity_id_to_class_map) == 0:
        for entity_class in _onu_custom_entity_classes:
            log.info('adding-custom-me', class_id=entity_class.class_id)
            assert entity_class.class_id not in _onu_custom_entity_id_to_class_map, \
                "Class ID '{}' already exists in the class map".format(entity_class.class_id)
            _onu_custom_entity_id_to_class_map[entity_class.class_id] = entity_class

    log.info('onu_custom_me_entities', map=_onu_custom_entity_id_to_class_map)
    return _onu_custom_entity_id_to_class_map

