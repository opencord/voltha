#
# Copyright 2016 the original author or authors.
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
import structlog
from enum import Enum
from scapy.fields import ByteField, StrFixedLenField, ConditionalField, Field
from scapy.fields import ShortField
from scapy.packet import Packet

from voltha.extensions.omci.omci_defs import AttributeAccess
from voltha.extensions.omci.omci_entities import entity_id_to_class_map


log = structlog.get_logger()


class OmciData(Field):

    __slots__ = Field.__slots__ + ['_entity_class']

    def __init__(self, name, entity_class="entity_class"):
        Field.__init__(self, name=name, default=None, fmt='s')
        self._entity_class = entity_class

    def addfield(self, pkt, s, val):
        class_id = getattr(pkt, self._entity_class)
        entity_class = entity_id_to_class_map.get(class_id)
        for attribute in entity_class.attributes:
            if AttributeAccess.SetByCreate not in attribute._access:
                continue
            if attribute._fld.name == 'managed_entity_id':
                continue
            fld = attribute._fld
            s = fld.addfield(pkt, s, val.get(fld.name, fld.default))
        return s

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        class_id = getattr(pkt, self._entity_class)
        entity_class = entity_id_to_class_map.get(class_id)
        data = {}
        for attribute in entity_class.attributes:
            if AttributeAccess.SetByCreate not in attribute._access:
                continue
            if attribute._fld.name == 'managed_entity_id':
                continue
            fld = attribute._fld
            s, value = fld.getfield(pkt, s)
            data[fld.name] = value
        return s, data


class OmciMaskedData(Field):

    __slots__ = Field.__slots__ + ['_entity_class', '_attributes_mask']

    def __init__(self, name, entity_class="entity_class",
                 attributes_mask="attributes_mask"):
        Field.__init__(self, name=name, default=None, fmt='s')
        self._entity_class = entity_class
        self._attributes_mask = attributes_mask

    def addfield(self, pkt, s, val):
        class_id = getattr(pkt, self._entity_class)
        attribute_mask = getattr(pkt, self._attributes_mask)
        entity_class = entity_id_to_class_map.get(class_id)
        indices = entity_class.attribute_indices_from_mask(attribute_mask)
        for index in indices:
            fld = entity_class.attributes[index]._fld
            s = fld.addfield(pkt, s, val[fld.name])
        return s

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        class_id = getattr(pkt, self._entity_class)
        attribute_mask = getattr(pkt, self._attributes_mask)
        entity_class = entity_id_to_class_map[class_id]
        indices = entity_class.attribute_indices_from_mask(attribute_mask)
        data = {}
        for index in indices:
            try:
                fld = entity_class.attributes[index]._fld
            except IndexError, e:
                log.error("Cannot decode attribute {} for entity class {}".format(
                        index, entity_class))
                continue
            try:
                s, value = fld.getfield(pkt, s)
            except Exception, e:
                raise
            data[fld.name] = value
        return  s, data


class OmciMessage(Packet):
    name = "OmciMessage"
    message_id = None  # OMCI message_type value, filled by derived classes
    fields_desc = []


class OmciCreate(OmciMessage):
    name = "OmciCreate"
    message_id = 0x44
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        OmciData("data")
    ]


class OmciCreateResponse(OmciMessage):
    name = "OmciCreateResponse"
    message_id = 0x24
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", None),
        ByteField("success_code", 0),
        ShortField("parameter_error_attributes_mask", None),
    ]


class OmciDelete(OmciMessage):
    name = "OmciDelete"
    message_id = 0x46
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", None),
    ]


class OmciDeleteResponse(OmciMessage):
    name = "OmciDeleteResponse"
    message_id = 0x26
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", None),
        ByteField("success_code", 0),
    ]


class OmciSet(OmciMessage):
    name = "OmciSet"
    message_id = 0x48
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None),
        OmciMaskedData("data")
    ]


class OmciSetResponse(OmciMessage):
    name = "OmciSetResponse"
    message_id = 0x28
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", None),
        ByteField("success_code", 0),
        ShortField("unsupported_attributes_mask", None),
        ShortField("failed_attributes_mask", None),
    ]


class OmciGet(OmciMessage):
    name = "OmciGet"
    message_id = 0x49
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None)
    ]


class OmciGetResponse(OmciMessage):
    name = "OmciGetResponse"
    message_id = 0x29
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0),
        ShortField("attributes_mask", None),
        ConditionalField(
            OmciMaskedData("data"), lambda pkt: pkt.success_code == 0)
    ]


class OmciGetAllAlarms(OmciMessage):
    name = "OmciGetAllAlarms"
    message_id = 0x4b
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),  # Always 0 (ONT instance)
        ByteField("alarm_retrieval_mode", 0)  # 0 or 1
    ]


class OmciGetAllAlarmsResponse(OmciMessage):
    name = "OmciGetAllAlarmsResponse"
    message_id = 0x2b
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("number_of_commands", None)
    ]


class OmciGetAllAlarmsNext(OmciMessage):
    name = "OmciGetAllAlarmsNext"
    message_id = 0x4c
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("command_sequence_number", None)
    ]


class OmciGetAllAlarmsNextResponse(OmciMessage):
    name = "OmciGetAllAlarmsNextResponse"
    message_id = 0x2c
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("alarmed_entity_class", None),
        ShortField("alarmed_entity_id", 0),
        StrFixedLenField("alarm_bit_map", None, 27)  # TODO better type?
    ]


class OmciMibUpload(OmciMessage):
    name = "OmciMibUpload"
    message_id = 0x4d
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
    ]


class OmciMibUploadResponse(OmciMessage):
    name = "OmciMibUploadResponse"
    message_id = 0x2d
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("number_of_commands", None)
    ]


class OmciMibUploadNext(OmciMessage):
    name = "OmciMibUploadNext"
    message_id = 0x4e
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("command_sequence_number", None)
    ]


class OmciMibUploadNextResponse(OmciMessage):
    name = "OmciMibUploadNextResponse"
    message_id = 0x2e
    fields_desc = [
        ShortField("entity_class", 2),  # Always 2 (ONT data)
        ShortField("entity_id", 0),
        ShortField("object_entity_class", None),
        ShortField("object_entity_id", 0),
        ShortField("object_attributes_mask", None),
        OmciMaskedData("object_data", entity_class='object_entity_class',
                       attributes_mask='object_attributes_mask')
    ]


class OmciMibReset(OmciMessage):
    name = "OmciMibReset"
    message_id = 0x4f
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0)
    ]


class OmciMibResetResponse(OmciMessage):
    name = "OmciMibResetResponse"
    message_id = 0x2f
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0)
    ]
