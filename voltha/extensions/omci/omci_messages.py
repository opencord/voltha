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
import structlog
from scapy.fields import ByteField, ThreeBytesField, StrFixedLenField, ConditionalField, IntField, Field
from scapy.fields import ShortField, BitField
from scapy.packet import Packet

from voltha.extensions.omci.omci_defs import AttributeAccess, OmciSectionDataSize
from voltha.extensions.omci.omci_fields import OmciTableField, OmciVariableLenZeroPadField
import voltha.extensions.omci.omci_entities as omci_entities


log = structlog.get_logger()


class OmciData(Field):

    __slots__ = Field.__slots__ + ['_entity_class']

    def __init__(self, name, entity_class="entity_class"):
        Field.__init__(self, name=name, default=None, fmt='s')
        self._entity_class = entity_class

    def addfield(self, pkt, s, val):
        class_id = getattr(pkt, self._entity_class)
        entity_class = omci_entities.entity_id_to_class_map.get(class_id)
        for attribute in entity_class.attributes:
            if AttributeAccess.SetByCreate not in attribute.access:
                continue
            if attribute.field.name == 'managed_entity_id':
                continue
            fld = attribute.field
            s = fld.addfield(pkt, s, val.get(fld.name, fld.default))
        return s

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        class_id = getattr(pkt, self._entity_class)
        entity_class = omci_entities.entity_id_to_class_map.get(class_id)
        data = {}
        for attribute in entity_class.attributes:
            if AttributeAccess.SetByCreate not in attribute.access:
                continue
            if attribute.field.name == 'managed_entity_id':
                continue
            fld = attribute.field
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
        entity_class = omci_entities.entity_id_to_class_map.get(class_id)
        indices = entity_class.attribute_indices_from_mask(attribute_mask)
        for index in indices:
            fld = entity_class.attributes[index].field
            s = fld.addfield(pkt, s, val[fld.name])
        return s

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""
        class_id = getattr(pkt, self._entity_class)
        attribute_mask = getattr(pkt, self._attributes_mask)
        entity_class = omci_entities.entity_id_to_class_map[class_id]
        indices = entity_class.attribute_indices_from_mask(attribute_mask)
        data = {}
        table_attribute_mask = 0
        for index in indices:
            try:
                fld = entity_class.attributes[index].field
            except IndexError, e:
                log.error("attribute-decode-failure", attribute_index=index,
                          entity_class=entity_class, e=e)
                continue
            try:
                s, value = fld.getfield(pkt, s)
            except Exception, _e:
                raise
            if isinstance(pkt, OmciGetResponse) and isinstance(fld, OmciTableField):
                data[fld.name + '_size'] = value
                table_attribute_mask = table_attribute_mask | (1 << (16 - index))
            else:
                data[fld.name] = value
        if table_attribute_mask:
            data['table_attribute_mask'] = table_attribute_mask
        return s, data


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
        ConditionalField(OmciMaskedData("data"),
                         lambda pkt: pkt.success_code in (0, 9)),
        ConditionalField(OmciVariableLenZeroPadField("zero_padding", 36),
                         lambda pkt: pkt.success_code == 9),

        # These fields are only valid if attribute error (status == 9)
        ConditionalField(ShortField("unsupported_attributes_mask", 0),
                         lambda pkt: pkt.success_code == 9),
        ConditionalField(ShortField("failed_attributes_mask", 0),
                         lambda pkt: pkt.success_code == 9)
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
        BitField("alarm_bit_map", None, 224)
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


class OmciAlarmNotification(OmciMessage):
    name = "AlarmNotification"
    message_id = 0x10
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        BitField("alarm_bit_map", 0, 224),
        ThreeBytesField("zero_padding", 0),
        ByteField("alarm_sequence_number", None)
    ]


class OmciAttributeValueChange(OmciMessage):
    name = "AttributeValueChange"
    message_id = 0x11
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None),
        OmciMaskedData("data")
    ]


class OmciReboot(OmciMessage):
    name = "OmciOnuReboot"
    message_id = 0x59
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("reboot_code", 0)
    ]


class OmciRebootResponse(OmciMessage):
    name = "OmciOnuRebootResponse"
    message_id = 0x39
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0)
    ]


class OmciGetNext(OmciMessage):
    name = "OmciGetNext"
    message_id = 0x5A
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None),
        ShortField("command_sequence_number", None)
    ]


class OmciGetNextResponse(OmciMessage):
    name = "OmciGetNextResponse"
    message_id = 0x3A
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0),
        ShortField("attributes_mask", None),
        ConditionalField(OmciMaskedData("data"),
                         lambda pkt: pkt.success_code == 0)
    ]


class OmciSynchronizeTime(OmciMessage):
    name = "OmciSynchronizeTime"
    message_id = 0x58
    fields_desc = [
        ShortField("entity_class", 256),  # OntG
        ShortField("entity_id", 0),
        ShortField("year", 0),       # eg) 2018
        ByteField("month", 0),       # 1..12
        ByteField("day", 0),         # 1..31
        ByteField("hour", 0),        # 0..23
        ByteField("minute", 0),      # 0..59
        ByteField("second", 0)       # 0..59
    ]


class OmciSynchronizeTimeResponse(OmciMessage):
    name = "OmciSynchronizeTimeResponse"
    message_id = 0x38
    fields_desc = [
        ShortField("entity_class", 256),  # OntG
        ShortField("entity_id", 0),
        ByteField("success_code", 0),
        ConditionalField(ShortField("success_info", None),
                         lambda pkt: pkt.success_code == 0)
    ]


class OmciGetCurrentData(OmciMessage):
    name = "OmciGetCurrentData"
    message_id = 0x5C
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None),
    ]


class OmciGetCurrentDataResponse(OmciMessage):
    name = "OmciGetCurrentDataResponse"
    message_id = 0x3C
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0),
        ShortField("attributes_mask", None),
        ShortField("unsupported_attributes_mask", None),
        ShortField("failed_attributes_mask", None),
        ConditionalField(
            OmciMaskedData("data"), lambda pkt: pkt.success_code == 0)
    ]


class OmciStartSoftwareDownload(OmciMessage):
    name = "OmciStartSoftwareDownload"
    message_id = 0x53
    fields_desc = [
        ShortField("entity_class", 7),  # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("window_size", 0),
        IntField("image_size", 0),
        ByteField("image_number", 1),   # Always only 1 in parallel
        ShortField("instance_id", None) # should be same as "entity_id"        
    ]


class OmciStartSoftwareDownloadResponse(OmciMessage):
    name = "OmciStartSoftwareDownloadResponse"
    message_id = 0x33
    fields_desc = [
        ShortField("entity_class", 7),  # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("result", 0),
        ByteField("window_size", 0),
        ByteField("image_number", 1),   # Always only 1 in parallel
        ShortField("instance_id", None) # should be same as "entity_id"        
    ]


class OmciEndSoftwareDownload(OmciMessage):
    name = "OmciEndSoftwareDownload"
    message_id = 0x55
    fields_desc = [
        ShortField("entity_class", 7),  # Always 7 (Software image)
        ShortField("entity_id", None),
        IntField("crc32", 0),
        IntField("image_size", 0),
        ByteField("image_number", 1),   # Always only 1 in parallel
        ShortField("instance_id", None),# should be same as "entity_id"
    ]


class OmciEndSoftwareDownloadResponse(OmciMessage):
    name = "OmciEndSoftwareDownload"
    message_id = 0x35
    fields_desc = [
        ShortField("entity_class", 7),  # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("result", 0),
        ByteField("image_number", 1),   # Always only 1 in parallel
        ShortField("instance_id", None),# should be same as "entity_id"
        ByteField("result0", 0)         # same as result 
    ]


class OmciDownloadSection(OmciMessage):
    name = "OmciDownloadSection"
    message_id = 0x14
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("section_number", 0),  # Always only 1 in parallel
        StrFixedLenField("data", 0, length=OmciSectionDataSize) # section data
    ]


class OmciDownloadSectionLast(OmciMessage):
    name = "OmciDownloadSection"
    message_id = 0x54
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("section_number", 0),  # Always only 1 in parallel
        StrFixedLenField("data", 0, length=OmciSectionDataSize) # section data
    ]


class OmciDownloadSectionResponse(OmciMessage):
    name = "OmciDownloadSectionResponse"
    message_id = 0x34
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("result", 0),
        ByteField("section_number", 0),  # Always only 1 in parallel
    ]


class OmciActivateImage(OmciMessage):
    name = "OmciActivateImage"
    message_id = 0x56
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("activate_flag", 0)    # Activate image unconditionally
    ]


class OmciActivateImageResponse(OmciMessage):
    name = "OmciActivateImageResponse"
    message_id = 0x36
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("result", 0)           # Activate image unconditionally
    ]


class OmciCommitImage(OmciMessage):
    name = "OmciCommitImage"
    message_id = 0x57
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
    ]


class OmciCommitImageResponse(OmciMessage):
    name = "OmciCommitImageResponse"
    message_id = 0x37
    fields_desc = [
        ShortField("entity_class", 7),   # Always 7 (Software image)
        ShortField("entity_id", None),
        ByteField("result", 0)           # Activate image unconditionally
    ]

class OmciTest(OmciMessage):
    name = "OmciTest"
    message_id = 0x52
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField('self_test', 0x07)
    ]


class OmciTestResponse(OmciMessage):
    name = "OmciTesResponse"
    message_id = 0x32
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", None)
    ]

class OmciTestResult(OmciMessage):
    name = "TestResult"
    message_id = 0x1B
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("power_feed_voltage", 1),
        ShortField('received_optical_power', 3),
        ShortField('mean_optical_launch_power', 5),
        ShortField('laser_bias_current', 9),
        ShortField('temperature', 12)
    ]
