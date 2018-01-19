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

        self._class = entity_class
        self._entity_id = entity_id
        self.data = data

    def __str__(self):
        return '{}: Entity_ID: {}, Data: {}'.\
            format(self.entity_class_name, self._entity_id, self.data)

    @property
    def entity_class(self):
        """
        The Entity Class for this ME
        :return: (EntityClass) Entity class
        """
        return self._class

    @property
    def entity_class_name(self):
        return self._class.__class__.__name__

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
            raise TypeError("param '{}' should be a {}".format(param, types))

    def _check_operation(self, operation):
        allowed = self.entity_class.mandatory_operations | self.entity_class.optional_operations
        assert operation in allowed, "{} not allowed for '{}'".format(str(operation).split('.')[1],
                                                                      self.entity_class_name)

    def _check_attributes(self, attributes, access):
        for attribute in attributes:
            index = self.entity_class.attribute_name_to_index_map.get(attribute)
            # Bad attribute name (invalid or spelling error)?
            assert index is not None, "Attribute '{}' is not valid for '{}'".format(attribute,
                                                                                    self.entity_class_name)
            # Invalid access?
            # TODO: Add read-only access to EntityClass _access set. Currently it is protected
            assert access in self.entity_class.attributes[index]._access,\
                "No '{} access for attribute '{}".format(str(access).split('.')[1], attribute)

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
        self._check_attributes(data.keys(), AA.Writable)

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
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
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
        self._check_attributes(data.keys(), AA.Writable)

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
