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
import copy
from mib_db_api import *
import json


class MibDbVolatileDict(MibDbApi):
    """
    A very simple in-memory database for ME storage. Data is not persistent
    across reboots.

    In Phase 2, this DB will be instantiated on a per-ONU basis but act as if
    it is shared for all ONUs. This class will be updated with and external
    key-value store (or other appropriate database) in Voltha 1.3 Sprint 3

    This class can be used for unit tests
    """
    CURRENT_VERSION = 1

    def __init__(self, omci_agent):
        """
        Class initializer
        :param omci_agent: (OpenOMCIAgent) OpenOMCI Agent
        """
        super(MibDbVolatileDict, self).__init__(omci_agent)
        self._data = dict()   # device_id -> ME ID -> Inst ID -> Attr Name -> Values

    def start(self):
        """
        Start up/restore the database. For in-memory, will be a nop. For external
        DB, may need to create the DB and fetch create/modified values
        """
        super(MibDbVolatileDict, self).start()
        # TODO: Delete this method if nothing else is done except calling the base class

    def stop(self):
        """
        Start up the database. For in-memory, will be a nop. For external
        DB, may need to create the DB and fetch create/modified values
        """
        super(MibDbVolatileDict, self).stop()
        # TODO: Delete this method if nothing else is done except calling the base class

    def add(self, device_id, overwrite=False):
        """
        Add a new ONU to database

        :param device_id: (str) Device ID of ONU to add
        :param overwrite: (bool) Overwrite existing entry if found.

        :raises KeyError: If device already exist and 'overwrite' is False
        """
        self.log.debug('add-device', device_id=device_id, overwrite=overwrite)

        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        if not overwrite and device_id in self._data:
            raise KeyError('Device {} already exists in the database'
                           .format(device_id))

        now = datetime.utcnow()
        self._data[device_id] = {
            DEVICE_ID_KEY: device_id,
            CREATED_KEY: now,
            LAST_SYNC_KEY: None,
            MDS_KEY: 0,
            VERSION_KEY: MibDbVolatileDict.CURRENT_VERSION,
            ME_KEY: dict(),
            MSG_TYPE_KEY: set()
        }

    def remove(self, device_id):
        """
        Remove an ONU from the database

        :param device_id: (str) Device ID of ONU to remove from database
        """
        self.log.debug('remove-device', device_id=device_id)

        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        if device_id in self._data:
            del self._data[device_id]
            self._modified = datetime.utcnow()

    def on_mib_reset(self, device_id):
        """
        Reset/clear the database for a specific Device

        :param device_id: (str) ONU Device ID
        :raises DatabaseStateError: If the database is not enabled
        :raises KeyError: If the device does not exist in the database
        """
        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        device_db = self._data[device_id]
        self._modified = datetime.utcnow()

        self._data[device_id] = {
            DEVICE_ID_KEY: device_id,
            CREATED_KEY: device_db[CREATED_KEY],
            LAST_SYNC_KEY: device_db[LAST_SYNC_KEY],
            MDS_KEY: 0,
            VERSION_KEY: MibDbVolatileDict.CURRENT_VERSION,
            ME_KEY: device_db[ME_KEY],
            MSG_TYPE_KEY: device_db[MSG_TYPE_KEY]
        }

    def save_mib_data_sync(self, device_id, value):
        """
        Save the MIB Data Sync to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (int) Value to save
        """
        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if not isinstance(value, int):
            raise TypeError('MIB Data Sync is an integer')

        if not 0 <= value <= 255:
            raise ValueError('Invalid MIB-data-sync value {}.  Must be 0..255'.
                             format(value))

        self._data[device_id][MDS_KEY] = value
        self._modified = datetime.utcnow()

    def get_mib_data_sync(self, device_id):
        """
        Get the MIB Data Sync value last saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if device_id not in self._data:
            return None

        return self._data[device_id].get(MDS_KEY)

    def save_last_sync(self, device_id, value):
        """
        Save the Last Sync time to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (DateTime) Value to save
        """
        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if not isinstance(value, datetime):
            raise TypeError('Expected a datetime object, got {}'.
                            format(type(datetime)))

        self._data[device_id][LAST_SYNC_KEY] = value
        self._modified = datetime.utcnow()

    def get_last_sync(self, device_id):
        """
        Get the Last SYnc Time saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if device_id not in self._data:
            return None

        return self._data[device_id].get(LAST_SYNC_KEY)

    def set(self, device_id, class_id, instance_id, attributes):
        """
        Set a database value.  This should only be called by the MIB synchronizer
        and its related tasks

        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param instance_id: (int) ME Entity ID
        :param attributes: (dict) Attribute dictionary

        :returns: (bool) True if the value was saved to the database. False if the
                         value was identical to the current instance

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be a string')

        if not 0 <= class_id <= 0xFFFF:
            raise ValueError("Invalid Class ID: {}, should be 0..65535".format(class_id))

        if not 0 <= instance_id <= 0xFFFF:
            raise ValueError("Invalid Instance ID: {}, should be 0..65535".format(instance_id))

        if not isinstance(attributes, dict):
            raise TypeError("Attributes should be a dictionary")

        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        now = datetime.utcnow()
        try:
            device_db = self._data[device_id]
            class_db = device_db.get(class_id)
            created = False

            if class_db is None:
                device_db[class_id] = {CLASS_ID_KEY: class_id}

                class_db = device_db[class_id]
                self._modified = now
                created = True

            instance_db = class_db.get(instance_id)
            if instance_db is None:
                class_db[instance_id] = {
                    INSTANCE_ID_KEY: instance_id,
                    CREATED_KEY: now,
                    MODIFIED_KEY: now,
                    ATTRIBUTES_KEY: dict()
                }
                instance_db = class_db[instance_id]
                self._modified = now
                created = True

            changed = False

            me_map = self._omci_agent.get_device(device_id).me_map
            entity = me_map.get(class_id)

            for attribute, value in attributes.items():
                assert isinstance(attribute, basestring)
                assert value is not None, "Attribute '{}' value cannot be 'None'".\
                    format(attribute)

                db_value = instance_db[ATTRIBUTES_KEY].get(attribute) \
                    if ATTRIBUTES_KEY in instance_db else None

                if entity is not None and isinstance(value, basestring):
                    from scapy.fields import StrFixedLenField
                    attr_index = entity.attribute_name_to_index_map[attribute]
                    eca = entity.attributes[attr_index]
                    field = eca.field

                    if isinstance(field, StrFixedLenField):
                        from scapy.base_classes import Packet_metaclass
                        if isinstance(field.default, Packet_metaclass) \
                                and hasattr(field.default, 'json_from_value'):
                            # Value/hex of Packet Class to string
                            value = field.default.json_from_value(value)

                if entity is not None and attribute in entity.attribute_name_to_index_map:
                    attr_index = entity.attribute_name_to_index_map[attribute]
                    eca = entity.attributes[attr_index]
                    field = eca.field

                    if hasattr(field, 'to_json'):
                        value = field.to_json(value, db_value)

                # Complex packet types may have an attribute encoded as an object, this
                # can be check by seeing if there is a to_json() conversion callable
                # defined
                if hasattr(value, 'to_json'):
                    value = value.to_json()

                # Other complex packet types may be a repeated list field (FieldListField)
                elif isinstance(value, (list, dict)):
                    value = json.dumps(value, separators=(',', ':'))

                assert db_value is None or isinstance(value, type(db_value)), \
                    "New value type for attribute '{}' type is changing from '{}' to '{}'".\
                    format(attribute, type(db_value), type(value))

                if db_value is None or db_value != value:
                    instance_db[ATTRIBUTES_KEY][attribute] = value
                    changed = True

            if changed:
                instance_db[MODIFIED_KEY] = now
                self._modified = now

            return changed or created

        except Exception as e:
            self.log.error('set-failure', e=e, class_id=class_id,
                           instance_id=instance_id, attributes=attributes)
            raise

    def delete(self, device_id, class_id, instance_id):
        """
        Delete an entity from the database if it exists.  If all instances
        of a class are deleted, the class is deleted as well.

        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param instance_id: (int) ME Entity ID

        :returns: (bool) True if the instance was found and deleted. False
                         if it did not exist.

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        if not isinstance(device_id, basestring):
            raise TypeError('Device ID should be an string')

        if not 0 <= class_id <= 0xFFFF:
            raise ValueError('class-id is 0..0xFFFF')

        if not 0 <= instance_id <= 0xFFFF:
            raise ValueError('instance-id is 0..0xFFFF')

        try:
            device_db = self._data[device_id]
            class_db = device_db.get(class_id)

            if class_db is None:
                return False

            instance_db = class_db.get(instance_id)
            if instance_db is None:
                return False

            now = datetime.utcnow()
            del class_db[instance_id]

            if len(class_db) == 1:      # Is only 'CLASS_ID_KEY' remaining
                del device_db[class_id]

            self._modified = now
            return True

        except Exception as e:
            self.log.error('delete-failure', e=e)
            raise

    def query(self, device_id, class_id=None, instance_id=None, attributes=None):
        """
        Get database information.

        This method can be used to request information from the database to the detailed
        level requested

        :param device_id: (str) ONU Device ID
        :param class_id:  (int) Managed Entity class ID
        :param instance_id: (int) Managed Entity instance
        :param attributes: (list/set or str) Managed Entity instance's attributes

        :return: (dict) The value(s) requested. If class/inst/attribute is
                        not found, an empty dictionary is returned
        :raises KeyError: If the requested device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        self.log.debug('query', device_id=device_id, class_id=class_id,
                       instance_id=instance_id, attributes=attributes)

        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        if not isinstance(device_id, basestring):
            raise TypeError('Device ID is a string')

        device_db = self._data[device_id]
        if class_id is None:
            return self._fix_dev_json_attributes(copy.copy(device_db), device_id)

        if not isinstance(class_id, int):
            raise TypeError('Class ID is an integer')

        me_map = self._omci_agent.get_device(device_id).me_map
        entity = me_map.get(class_id)

        class_db = device_db.get(class_id, dict())
        if instance_id is None or len(class_db) == 0:
            return self._fix_cls_json_attributes(copy.copy(class_db), entity)

        if not isinstance(instance_id, int):
            raise TypeError('Instance ID is an integer')

        instance_db = class_db.get(instance_id, dict())
        if attributes is None or len(instance_db) == 0:
            return self._fix_inst_json_attributes(copy.copy(instance_db), entity)

        if not isinstance(attributes, (basestring, list, set)):
            raise TypeError('Attributes should be a string or list/set of strings')

        if not isinstance(attributes, (list, set)):
            attributes = [attributes]

        results = {attr: val for attr, val in instance_db[ATTRIBUTES_KEY].iteritems()
                   if attr in attributes}

        for attr, attr_data in results.items():
            attr_index = entity.attribute_name_to_index_map[attr]
            eca = entity.attributes[attr_index]
            results[attr] = self._fix_attr_json_attribute(copy.copy(attr_data), eca)

        return results

    #########################################################################
    # Following routines are used to fix-up JSON encoded complex data. A
    # nice side effect is that the values returned will be a deep-copy of
    # the class/instance/attribute data of what is in the database. Note
    # That other database values (created, modified, ...) will still reference
    # back to the original DB.

    def _fix_dev_json_attributes(self, dev_data, device_id):
        for cls_id, cls_data in dev_data.items():
            if isinstance(cls_id, int):
                me_map = self._omci_agent.get_device(device_id).me_map
                entity = me_map.get(cls_id)
                dev_data[cls_id] = self._fix_cls_json_attributes(copy.copy(cls_data), entity)
        return dev_data

    def _fix_cls_json_attributes(self, cls_data, entity):
        for inst_id, inst_data in cls_data.items():
            if isinstance(inst_id, int):
                cls_data[inst_id] = self._fix_inst_json_attributes(copy.copy(inst_data), entity)
        return cls_data

    def _fix_inst_json_attributes(self, inst_data, entity):
        if ATTRIBUTES_KEY in inst_data:
            for attr, attr_data in inst_data[ATTRIBUTES_KEY].items():
                attr_index = entity.attribute_name_to_index_map[attr] \
                    if entity is not None and attr in entity.attribute_name_to_index_map else None
                eca = entity.attributes[attr_index] if attr_index is not None else None
                inst_data[ATTRIBUTES_KEY][attr] = self._fix_attr_json_attribute(copy.copy(attr_data), eca)
        return inst_data

    def _fix_attr_json_attribute(self, attr_data, eca):

        try:
            if eca is not None:
                field = eca.field
                if hasattr(field, 'load_json'):
                    value = field.load_json(attr_data)
                    return value

            return json.loads(attr_data) if isinstance(attr_data, basestring) else attr_data

        except ValueError:
            return attr_data

        except Exception as e:
            pass

    def update_supported_managed_entities(self, device_id, managed_entities):
        """
        Update the supported OMCI Managed Entities for this device

        :param device_id: (str) ONU Device ID
        :param managed_entities: (set) Managed Entity class IDs
        """
        now = datetime.utcnow()
        try:
            device_db = self._data[device_id]

            entities = {class_id: self._managed_entity_to_name(device_id, class_id)
                        for class_id in managed_entities}

            device_db[ME_KEY] = entities
            self._modified = now

        except Exception as e:
            self.log.error('set-me-failure', e=e)
            raise

    def _managed_entity_to_name(self, device_id, class_id):
        me_map = self._omci_agent.get_device(device_id).me_map
        entity = me_map.get(class_id)

        return entity.__name__ if entity is not None else 'UnknownManagedEntity'

    def update_supported_message_types(self, device_id, msg_types):
        """
        Update the supported OMCI Managed Entities for this device

        :param device_id: (str) ONU Device ID
        :param msg_types: (set) Message Type values (ints)
        """
        now = datetime.utcnow()
        try:
            msg_type_set = {msg_type.value for msg_type in msg_types}
            self._data[device_id][MSG_TYPE_KEY] = msg_type_set
            self._modified = now

        except Exception as e:
            self.log.error('set-me-failure', e=e)
            raise
