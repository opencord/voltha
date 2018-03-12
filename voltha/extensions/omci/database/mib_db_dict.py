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

        :raises KeyError: If device does not exist and 'overwrite' is False
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
            CREATED_KEY: now,
            MODIFIED_KEY: now,
            MDS_KEY: 0,
            LAST_SYNC_KEY: None,
            VERSION_KEY: MibDbVolatileDict.CURRENT_VERSION
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

    def on_mib_reset(self, device_id):
        """
        Reset/clear the database for a specific Device

        :param device_id: (str) ONU Device ID
        :raises DatabaseStateError: If the database is not enabled
        """
        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        now = datetime.utcnow()
        device_db = self._data.get(device_id)

        if device_db is None:
            self._data[device_id] = {
                CREATED_KEY: now,
                LAST_SYNC_KEY: None
            }
            device_db = self._data[device_id]
        else:
            created = device_db[CREATED_KEY]
            last_sync = device_db[LAST_SYNC_KEY]

            self._data[device_id] = {
                CREATED_KEY: created,
                LAST_SYNC_KEY: last_sync
            }

        device_db[MODIFIED_KEY] = now
        device_db[MDS_KEY] = 0
        device_db[VERSION_KEY] = MibDbVolatileDict.CURRENT_VERSION
        self._modified = now

    def save_mib_data_sync(self, device_id, value):
        """
        Save the MIB Data Sync to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (int) Value to save
        """
        if device_id in self._data:
            assert 0 <= value <= 255,\
                'Invalid MIB Data Sync Value: {}'.format(value)

            self._data[device_id][MODIFIED_KEY] = datetime.utcnow()
            self._data[device_id][MDS_KEY] = value

    def get_mib_data_sync(self, device_id):
        """
        Get the MIB Data Sync value last saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        if device_id not in self._data:
            return None

        return self._data[device_id].get(MDS_KEY)

    def save_last_sync(self, device_id, value):
        """
        Save the Last Sync time to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (DateTime) Value to save
        """
        if device_id in self._data:
            self._data[device_id][MODIFIED_KEY] = datetime.utcnow()
            self._data[device_id][LAST_SYNC_KEY] = value

    def get_last_sync(self, device_id):
        """
        Get the Last SYnc Time saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        if device_id not in self._data:
            return None

        return self._data[device_id].get(LAST_SYNC_KEY)

    def set(self, device_id, class_id, entity_id, attributes):
        """
        Set a database value.  This should only be called by the MIB synchronizer
        and its related tasks

        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Entity ID
        :param attributes: (dict) Attribute dictionary

        :returns: (bool) True if the value was saved to the database. False if the
                         value was identical to the current instance

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        now = datetime.utcnow()
        try:
            device_db = self._data[device_id]
            class_db = device_db.get(class_id)

            if class_db is None:
                device_db[class_id] = {
                    CREATED_KEY: now,
                    MODIFIED_KEY: now
                }
                class_db = device_db[class_id]
                self._modified = now

            instance_db = class_db.get(entity_id)
            if instance_db is None:
                class_db[entity_id] = {
                    CREATED_KEY: now,
                    MODIFIED_KEY: now
                }
                instance_db = class_db[entity_id]
                class_db[MODIFIED_KEY] = now
                device_db[MODIFIED_KEY] = now
                self._modified = now

            changed = False

            for attribute, value in attributes.items():
                assert isinstance(attribute, basestring)
                assert value is not None, "Attribute '{}' value cannot be 'None'".\
                    format(attribute)

                db_value = instance_db.get(attribute)
                assert db_value is None or isinstance(value, type(db_value)), \
                    "New value for attribute '{}' type is changing from '{}' to '{}'".\
                        format(attribute, type(db_value), type(value))

                if db_value is None or db_value != value:
                    instance_db[attribute] = value
                    changed = True

                    instance_db[MODIFIED_KEY] = now
                    class_db[MODIFIED_KEY] = now
                    device_db[MODIFIED_KEY] = now
                    self._modified = now

            return changed

        except Exception as e:
            self.log.error('set-failure', e=e)
            raise

    def delete(self, device_id, class_id, entity_id):
        """
        Delete an entity from the database if it exists.  If all instances
        of a class are deleted, the class is deleted as well.

        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Entity ID

        :returns: (bool) True if the instance was found and deleted. False
                         if it did not exist.

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        if not self._started:
            raise DatabaseStateError('The Database is not currently active')

        try:
            device_db = self._data[device_id]
            class_db = device_db.get(class_id)

            if class_db is None:
                return False

            instance_db = class_db.get(entity_id)
            if instance_db is None:
                return False

            now = datetime.utcnow()
            del class_db[entity_id]

            if len(class_db) == len([CREATED_KEY, MODIFIED_KEY]):
                del device_db[class_id]
            else:
                class_db[MODIFIED_KEY] = now
            device_db[MODIFIED_KEY] = now
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
        :param attributes: (list or str) Managed Entity instance's attributes

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
            return device_db            # TODO: copy.deepcopy(device_db)

        if not isinstance(class_id, int):
            raise TypeError('Class ID is an integer')

        class_db = device_db.get(class_id, dict())
        if instance_id is None or len(class_db) == 0:
            return class_db         # TODO: copy.deepcopy(class_db)

        if not isinstance(instance_id, int):
            raise TypeError('Instance ID is an integer')

        instance_db = class_db.get(instance_id, dict())
        if attributes is None or len(instance_db) == 0:
            return instance_db              # TODO: copy.deepcopy(instance_db)

        if not isinstance(attributes, (basestring, list)):
            raise TypeError('Attributes should be a string or list of strings')

        if not isinstance(attributes, list):
            attributes = [attributes]

        return {attr: val for attr, val in instance_db.iteritems()
                if attr in attributes}
