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
OMCI Managed Entity Message support base class
"""
from voltha.extensions.omci.omci import *

# abbreviations
OP = EntityOperations
AA = AttributeAccess


class MEFrame(object):
    """Base class to help simplify Frame Creation"""
    def __init__(self, entity_class, entity_id, data):
        assert issubclass(entity_class, EntityClass), \
            "'{}' must be a subclass of MEFrame".format(entity_class)
        self.check_type(entity_id, int)

        if not 0 <= entity_id <= 0xFFFF:
            raise ValueError('entity_id should be 0..65535')

        self.log = structlog.get_logger()
        self._class = entity_class
        self._entity_id = entity_id
        self.data = data

    def __str__(self):
        return '{}: Entity_ID: {}, Data: {}'.\
            format(self.entity_class_name, self._entity_id, self.data)

    def __repr__(self):
        return str(self)

    @property
    def entity_class(self):
        """
        The Entity Class for this ME
        :return: (EntityClass) Entity class
        """
        return self._class

    @property
    def entity_class_name(self):
        return self._class.__name__

    @property
    def entity_id(self):
        """
        The Entity ID for this ME frame
        :return: (int) Entity ID (0..0xFFFF)
        """
        return self._entity_id

    @staticmethod
    def check_type(param, types):
        if not isinstance(param, types):
            raise TypeError("Parameter '{}' should be a {}".format(param, types))

    def _check_operation(self, operation):
        allowed = self.entity_class.mandatory_operations | self.entity_class.optional_operations
        assert operation in allowed, "{} not allowed for '{}'".format(operation.name,
                                                                      self.entity_class_name)

    def _check_attributes(self, attributes, access):
        keys = attributes.keys() if isinstance(attributes, dict) else attributes
        for attr_name in keys:
            # Bad attribute name (invalid or spelling error)?
            index = self.entity_class.attribute_name_to_index_map.get(attr_name)
            if index is None:
                raise KeyError("Attribute '{}' is not valid for '{}'".
                               format(attr_name, self.entity_class_name))
            # Invalid access?
            assert access in self.entity_class.attributes[index].access, \
                "Access '{}' for attribute '{}' is not valid for '{}'".format(access.name,
                                                                              attr_name,
                                                                              self.entity_class_name)

        if access.value in [AA.W.value, AA.SBC.value] and isinstance(attributes, dict):
            for attr_name, value in attributes.iteritems():
                index = self.entity_class.attribute_name_to_index_map.get(attr_name)
                attribute = self.entity_class.attributes[index]
                if not attribute.valid(value):
                    raise ValueError("Invalid value '{}' for attribute '{}' of '{}".
                                     format(value, attr_name, self.entity_class_name))

    @staticmethod
    def _attr_to_data(attributes):
        """
        Convert an object into the 'data' set or dictionary for get/set/create/delete
        requests.

        This method takes a 'string', 'list', or 'set' for get requests and
        converts it to a 'set' of attributes.

        For create/set requests a dictionary of attribute/value pairs is required

        :param attributes: (basestring, list, set, dict) attributes. For gets
                           a string, list, set, or dict can be provided. For create/set
                           operations, a dictionary should be provided. For delete
                           the attributes may be None since they are ignored.

        :return: (set, dict) set for get/deletes, dict for create/set
        """
        if isinstance(attributes, basestring):
            # data = [str(attributes)]
            data = set()
            data.add(str(attributes))

        elif isinstance(attributes, list):
            assert all(isinstance(attr, basestring) for attr in attributes),\
                'attribute list must be strings'
            data = {str(attr) for attr in attributes}
            assert len(data) == len(attributes), 'Attributes were not unique'

        elif isinstance(attributes, set):
            assert all(isinstance(attr, basestring) for attr in attributes),\
                'attribute set must be strings'
            data = {str(attr) for attr in attributes}

        elif isinstance(attributes, (dict, type(None))):
            data = attributes

        else:
            raise TypeError("Unsupported attributes type '{}'".format(type(attributes)))

        return data

    def create(self):
        """
        Create a Create request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        assert hasattr(self.entity_class, 'class_id'), 'class_id required for Create actions'
        assert hasattr(self, 'entity_id'), 'entity_id required for Create actions'
        assert hasattr(self, 'data'), 'data required for Create actions'

        data = getattr(self, 'data')
        MEFrame.check_type(data, dict)
        assert len(data) > 0, 'No attributes supplied'

        self._check_operation(OP.Create)
        self._check_attributes(data, AA.Writable)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                data=data
            ))

    def delete(self):
        """
        Create a Delete request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.Delete)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciDelete.message_id,
            omci_message=OmciDelete(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id')
            ))

    def set(self):
        """
        Create a Set request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        assert hasattr(self, 'data'), 'data required for Set actions'
        data = getattr(self, 'data')
        MEFrame.check_type(data, dict)
        assert len(data) > 0, 'No attributes supplied'

        self._check_operation(OP.Set)
        self._check_attributes(data, AA.Writable)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                attributes_mask=self.entity_class.mask_for(*data.keys()),
                data=data
            ))

    def get(self):
        """
        Create a Get request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        assert hasattr(self, 'data'), 'data required for Get actions'
        data = getattr(self, 'data')
        MEFrame.check_type(data, (list, set, dict))
        assert len(data) > 0, 'No attributes supplied'

        mask_set = data.keys() if isinstance(data, dict) else data

        self._check_operation(OP.Get)
        self._check_attributes(mask_set, AA.Readable)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                attributes_mask=self.entity_class.mask_for(*mask_set)
            ))

    def reboot(self, reboot_code=0):
        """
        Create a Reboot request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.Reboot)
        assert 0 <= reboot_code <= 2, 'Reboot code must be 0..2'

        return OmciFrame(
            transaction_id=None,
            message_type=OmciReboot.message_id,
            omci_message=OmciReboot(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                reboot_code=reboot_code
            ))

    def mib_reset(self):
        """
        Create a MIB Reset request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.MibReset)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id')
            ))

    def mib_upload(self):
        """
        Create a MIB Upload request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.MibUpload)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciMibUpload.message_id,
            omci_message=OmciMibUpload(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id')
            ))

    def mib_upload_next(self):
        """
        Create a MIB Upload Next request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        assert hasattr(self, 'data'), 'data required for Set actions'
        data = getattr(self, 'data')
        MEFrame.check_type(data, dict)
        assert len(data) > 0, 'No attributes supplied'
        assert 'mib_data_sync' in data, "'mib_data_sync' not in attributes list"

        self._check_operation(OP.MibUploadNext)
        self._check_attributes(data, AA.Writable)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciMibUploadNext.message_id,
            omci_message=OmciMibUploadNext(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                command_sequence_number=data['mib_data_sync']
            ))

    def get_next(self):
        """
        Create a Get Next request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        assert hasattr(self, 'data'), 'data required for Get Next actions'
        data = getattr(self, 'data')
        MEFrame.check_type(data, dict)
        assert len(data) == 1, 'Only one attribute should be specified'

        mask_set = data.keys() if isinstance(data, dict) else data

        self._check_operation(OP.GetNext)
        self._check_attributes(mask_set, AA.Readable)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciGetNext.message_id,
            omci_message=OmciGetNext(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                attributes_mask=self.entity_class.mask_for(*mask_set),
                command_sequence_number=data.values()[0]
            ))

    def synchronize_time(self, time=None):
        """
        Create a Synchronize Time request from for this ME
        :param time: (DateTime) Time to set to. If none, use UTC
        :return: (OmciFrame) OMCI Frame
        """
        from datetime import datetime
        self._check_operation(OP.SynchronizeTime)
        dt = time or datetime.utcnow()

        return OmciFrame(
            transaction_id=None,
            message_type=OmciSynchronizeTime.message_id,
            omci_message=OmciSynchronizeTime(
                    entity_class=getattr(self.entity_class, 'class_id'),
                    entity_id=getattr(self, 'entity_id'),
                    year=dt.year,
                    month=dt.month,
                    day=dt.day,
                    hour=dt.hour,
                    minute=dt.minute,
                    second=dt.second,
            ))

    def get_all_alarm(self, alarm_retrieval_mode):
        """
        Create a Alarm request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.GetAllAlarms)
        assert 0 <= alarm_retrieval_mode <= 1, 'Alarm retrieval mode must be 0..1'

        return OmciFrame(
            transaction_id=None,
            message_type=OmciGetAllAlarms.message_id,
            omci_message=OmciGetAllAlarms(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                alarm_retrieval_mode=alarm_retrieval_mode
            ))

    def get_all_alarm_next(self, command_sequence_number):
        """
        Create a Alarm request from for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.GetAllAlarmsNext)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciGetAllAlarmsNext.message_id,
            omci_message=OmciGetAllAlarmsNext(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                command_sequence_number=command_sequence_number
            ))

    def start_software_download(self, image_size, window_size):
        """
        Create Start Software Download message
        :return: (OmciFrame) OMCI Frame
        """
        self.log.debug("--> start_software_download")
        self._check_operation(OP.StartSoftwareDownload)
        return OmciFrame(
	            transaction_id=None,
	            message_type=OmciStartSoftwareDownload.message_id,
	            omci_message=OmciStartSoftwareDownload(
	                entity_class=getattr(self.entity_class, 'class_id'),
	                entity_id=getattr(self, 'entity_id'),
	                window_size=window_size,
	                image_size=image_size,
	                instance_id=getattr(self, 'entity_id')
	           ))
        
    def end_software_download(self, crc32, image_size):
        """
        Create End Software Download message
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.EndSoftwareDownload)
        return OmciFrame(
	            transaction_id=None,
	            message_type=OmciEndSoftwareDownload.message_id,
	            omci_message=OmciEndSoftwareDownload(
	                entity_class=getattr(self.entity_class, 'class_id'),
	                entity_id=getattr(self, 'entity_id'),
	                crc32=crc32,
	                image_size=image_size,
	                instance_id=getattr(self, 'entity_id')
	           ))
    
    def download_section(self, is_last_section, section_number, data):
        """
        Create Download Section message
        :is_last_section: (bool) indicate the last section in the window
        :section_num    : (int)  current section number
        :data           : (byte) data to be sent in the section
        :return: (OmciFrame) OMCI Frame
        """
        self.log.debug("--> download_section: ", section_number=section_number)
        
        self._check_operation(OP.DownloadSection)
        if is_last_section:
            return OmciFrame(
                    transaction_id=None,
                    message_type=OmciDownloadSectionLast.message_id,
                    omci_message=OmciDownloadSectionLast(
                        entity_class=getattr(self.entity_class, 'class_id'),
                        entity_id=getattr(self, 'entity_id'),
                        section_number=section_number,
                        data=data
                   ))
        else:
            return OmciFrame(
                    transaction_id=None,
                    message_type=OmciDownloadSection.message_id,
                    omci_message=OmciDownloadSection(
                        entity_class=getattr(self.entity_class, 'class_id'),
                        entity_id=getattr(self, 'entity_id'),
                        section_number=section_number,
                        data=data
                   ))

    def activate_image(self, activate_flag=0):
        """
        Activate Image message
        :activate_flag: 00	Activate image unconditionally
                        01	Activate image only if no POTS/VoIP calls are in progress
                        10	Activate image only if no emergency call is in progress
        :return: (OmciFrame) OMCI Frame
        """
        self.log.debug("--> activate_image", entity=self.entity_id, flag=activate_flag)
        return OmciFrame(
                transaction_id=None,
                message_type=OmciActivateImage.message_id,
                omci_message=OmciActivateImage(
                    entity_class=getattr(self.entity_class, 'class_id'),
                    entity_id=getattr(self, 'entity_id'),
                    activate_flag=activate_flag
               ))

    def commit_image(self):
        """
        Commit Image message
        :return: (OmciFrame) OMCI Frame
        """
        self.log.debug("--> commit_image", entity=self.entity_id)
        return OmciFrame(
                transaction_id=None,
                message_type=OmciCommitImage.message_id,
                omci_message=OmciCommitImage(
                    entity_class=getattr(self.entity_class, 'class_id'),
                    entity_id=getattr(self, 'entity_id'),
               ))

    def test(self):
        """
        Create a test request frame for this ME
        :return: (OmciFrame) OMCI Frame
        """
        self._check_operation(OP.Test)

        return OmciFrame(
            transaction_id=None,
            message_type=OmciTest.message_id,
            omci_message=OmciTest(
                entity_class=getattr(self.entity_class, 'class_id'),
                entity_id=getattr(self, 'entity_id'),
                self_test=0x07
            ))
