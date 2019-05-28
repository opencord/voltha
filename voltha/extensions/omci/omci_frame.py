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
from scapy.fields import ByteField, PacketField, IntField
from scapy.fields import ShortField, ConditionalField
from scapy.packet import Packet

from voltha.extensions.omci.omci_fields import FixedLenField
from voltha.extensions.omci.omci_messages import OmciCreate, OmciDelete, \
    OmciDeleteResponse, OmciSet, OmciSetResponse, OmciGet, OmciGetResponse, \
    OmciGetAllAlarms, OmciGetAllAlarmsResponse, OmciGetAllAlarmsNext, \
    OmciMibResetResponse, OmciMibReset, OmciMibUploadNextResponse, \
    OmciMibUploadNext, OmciMibUploadResponse, OmciMibUpload, \
    OmciGetAllAlarmsNextResponse, OmciAttributeValueChange, \
    OmciTestResult, OmciAlarmNotification, \
    OmciReboot, OmciRebootResponse, OmciGetNext, OmciGetNextResponse, \
    OmciSynchronizeTime, OmciSynchronizeTimeResponse, OmciGetCurrentData, \
    OmciGetCurrentDataResponse, OmciStartSoftwareDownload, OmciStartSoftwareDownloadResponse, \
    OmciDownloadSection, OmciDownloadSectionLast, OmciDownloadSectionResponse, \
    OmciEndSoftwareDownload, OmciEndSoftwareDownloadResponse, \
    OmciActivateImage, OmciActivateImageResponse, \
    OmciCommitImage, OmciCommitImageResponse, OmciTest, OmciTestResponse

from voltha.extensions.omci.omci_messages import OmciCreateResponse


class OmciFrame(Packet):
    name = "OmciFrame"
    fields_desc = [
        ShortField("transaction_id", 0),
        ByteField("message_type", None),
        ByteField("omci", 0x0a),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciCreate), align=36),
            lambda pkt: pkt.message_type == OmciCreate.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciCreateResponse), align=36),
            lambda pkt: pkt.message_type == OmciCreateResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciDelete), align=36),
            lambda pkt: pkt.message_type == OmciDelete.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciDeleteResponse), align=36),
            lambda pkt: pkt.message_type == OmciDeleteResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciSet), align=36),
            lambda pkt: pkt.message_type == OmciSet.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciSetResponse), align=36),
            lambda pkt: pkt.message_type == OmciSetResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGet), align=36),
            lambda pkt: pkt.message_type == OmciGet.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetResponse), align=36),
            lambda pkt: pkt.message_type == OmciGetResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetAllAlarms), align=36),
            lambda pkt: pkt.message_type == OmciGetAllAlarms.message_id),
        ConditionalField(FixedLenField(
            PacketField(
                "omci_message", None, OmciGetAllAlarmsResponse), align=36),
                lambda pkt:
                pkt.message_type == OmciGetAllAlarmsResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetAllAlarmsNext), align=36),
            lambda pkt: pkt.message_type == OmciGetAllAlarmsNext.message_id),
        ConditionalField(FixedLenField(
            PacketField(
                "omci_message", None, OmciGetAllAlarmsNextResponse), align=36),
                lambda pkt:
                pkt.message_type == OmciGetAllAlarmsNextResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibUpload), align=36),
            lambda pkt: pkt.message_type == OmciMibUpload.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibUploadResponse), align=36),
            lambda pkt: pkt.message_type == OmciMibUploadResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibUploadNext), align=36),
            lambda pkt:
                pkt.message_type == OmciMibUploadNext.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibUploadNextResponse), align=36),
            lambda pkt: pkt.message_type == OmciMibUploadNextResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibReset), align=36),
            lambda pkt: pkt.message_type == OmciMibReset.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciMibResetResponse), align=36),
            lambda pkt: pkt.message_type == OmciMibResetResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciAlarmNotification), align=36),
            lambda pkt: pkt.message_type == OmciAlarmNotification.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciAttributeValueChange), align=36),
            lambda pkt: pkt.message_type == OmciAttributeValueChange.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciReboot), align=36),
            lambda pkt: pkt.message_type == OmciReboot.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciRebootResponse), align=36),
            lambda pkt: pkt.message_type == OmciRebootResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetNext), align=36),
            lambda pkt: pkt.message_type == OmciGetNext.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetNextResponse), align=36),
            lambda pkt: pkt.message_type == OmciGetNextResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciSynchronizeTime), align=36),
            lambda pkt: pkt.message_type == OmciSynchronizeTime.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciSynchronizeTimeResponse), align=36),
            lambda pkt: pkt.message_type == OmciSynchronizeTimeResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetCurrentData), align=36),
            lambda pkt: pkt.message_type == OmciGetCurrentData.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciGetCurrentDataResponse), align=36),
            lambda pkt: pkt.message_type == OmciGetCurrentDataResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciStartSoftwareDownload), align=36),
            lambda pkt: pkt.message_type == OmciStartSoftwareDownload.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciStartSoftwareDownloadResponse), align=36),
            lambda pkt: pkt.message_type == OmciStartSoftwareDownloadResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciDownloadSection), align=36),
            lambda pkt: pkt.message_type == OmciDownloadSection.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciDownloadSectionLast), align=36),
            lambda pkt: pkt.message_type == OmciDownloadSectionLast.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciDownloadSectionResponse), align=36),
            lambda pkt: pkt.message_type == OmciDownloadSectionResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciEndSoftwareDownload), align=36),
            lambda pkt: pkt.message_type == OmciEndSoftwareDownload.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciEndSoftwareDownloadResponse), align=36),
            lambda pkt: pkt.message_type == OmciEndSoftwareDownloadResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciActivateImage), align=36),
            lambda pkt: pkt.message_type == OmciActivateImage.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciActivateImageResponse), align=36),
            lambda pkt: pkt.message_type == OmciActivateImageResponse.message_id),

        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciCommitImage), align=36),
            lambda pkt: pkt.message_type == OmciCommitImage.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciCommitImageResponse), align=36),
            lambda pkt: pkt.message_type == OmciCommitImageResponse.message_id),
        # Create Frame for Omci Test.
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciTest), align=36),
            lambda pkt: pkt.message_type == OmciTest.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciTestResponse), align=36),
            lambda pkt: pkt.message_type == OmciTestResponse.message_id),
        ConditionalField(FixedLenField(
            PacketField("omci_message", None, OmciTestResult), align=36),
            lambda pkt: pkt.message_type == OmciTestResult.message_id),

        # TODO add entries for remaining OMCI message types

        IntField("omci_trailer", 0x00000028)
    ]

    # We needed to patch the do_dissect(...) method of Packet, because
    # it wiped out already dissected conditional fields with None if they
    # referred to the same field name. We marked the only new line of code
    # with "Extra condition added".
    def do_dissect(self, s):
        raw = s
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if not s:
                break
            s, fval = f.getfield(self, s)
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            # Extra condition added
            if fval is not None or f.name not in self.fields:
                self.fields[f.name] = fval
        assert(raw.endswith(s))
        self.raw_packet_cache = raw[:-len(s)] if s else raw
        self.explicit = 1
        return s
