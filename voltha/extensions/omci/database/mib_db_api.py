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
OpenOMCI MIB Database API
"""

import structlog
from datetime import datetime

CREATED_KEY = 'created'
MODIFIED_KEY = 'modified'
MDS_KEY = 'mib_data_sync'
LAST_SYNC_KEY = 'last_mib_sync'
VERSION_KEY = 'version'
DEVICE_ID_KEY = 'device_id'
CLASS_ID_KEY = 'class_id'
INSTANCE_ID_KEY = 'instance_id'
ATTRIBUTES_KEY = 'attributes'
ME_KEY = 'managed_entities'
MSG_TYPE_KEY = 'message_types'


class DatabaseStateError(Exception):
    def __init__(self, *args):
        Exception.__init__(self, *args)


class MibDbApi(object):
    """
    MIB Database API Base Class

    Derive the ME MIB Database implementation from this API.  For an example
    implementation, look at the mib_db_dict.py implementation
    """
    def __init__(self, omci_agent):
        """
        Class initializer
        :param omci_agent: (OpenOMCIAgent) OpenOMCI Agent
        """
        self.log = structlog.get_logger()
        self._omci_agent = omci_agent
        self._started = False

        now = datetime.utcnow()
        self._created = now
        self._modified = now

    def start(self):
        """
        Start up/restore the database. For in-memory, will be a nop. For external
        DB, may need to create the DB and fetch create/modified values
        """
        if not self._started:
            self._started = True
        # For a derived class that is a persistent DB, Restore DB (connect,
        # get created/modified times, ....) or something along those lines.
        # Minimal restore could just be getting ONU device IDs' so they are cached
        # locally. Maximum restore would be a full in-memory version of database
        # for fast 'GET' request support.
        # Remember to restore the '_created' and '_modified' times (above) as well
        # from the database

    def stop(self):
        """
        Start up the database. For in-memory, will be a nop. For external
        DB, may need to create the DB and fetch create/modified values
        """
        if self._started:
            self._started = False

    @property
    def active(self):
        """
        Is the database active
        :return: (bool) True if active
        """
        return self._started

    @property
    def created(self):
        """
        Date (UTC) that the database was created
        :return: (datetime) creation date
        """
        return self._created

    @property
    def modified(self):
        """
        Date (UTC) that the database last added or removed a device
        or updated a device's ME information
        :return: (datetime) last modification date
        """
        return self._modified

    def add(self, device_id, overwrite=False):
        """
        Add a new ONU to database

        :param device_id: (str) Device ID of ONU to add
        :param overwrite: (bool) Overwrite existing entry if found.

        :raises KeyError: If device already exists and 'overwrite' is False
        """
        raise NotImplementedError('Implement this in your derive class')

    def remove(self, device_id):
        """
        Remove an ONU from the database

        :param device_id: (str) Device ID of ONU to remove from database
        """
        raise NotImplementedError('Implement this in your derive class')

    def set(self, device_id, class_id, entity_id, attributes):
        """
        Set/Create a database value.  This should only be called by the MIB synchronizer
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
        raise NotImplementedError('Implement this in your derive class')

    def delete(self, device_id, class_id, entity_id):
        """
        Delete an entity from the database if it exists

        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME Entity ID

        :returns: (bool) True if the instance was found and deleted. False
                         if it did not exist.

        :raises KeyError: If device does not exist
        :raises DatabaseStateError: If the database is not enabled
        """
        raise NotImplementedError('Implement this in your derive class')

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
        raise NotImplementedError('Implement this in your derive class')

    def on_mib_reset(self, device_id):
        """
        Reset/clear the database for a specific Device

        :param device_id: (str) ONU Device ID
        :raises DatabaseStateError: If the database is not enabled
        """
        # Your derived class should clear out all MIB data and update the
        # modified stats appropriately
        raise NotImplementedError('Implement this in your derive class')

    def save_mib_data_sync(self, device_id, value):
        """
        Save the MIB Data Sync to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (int) Value to save
        """
        raise NotImplementedError('Implement this in your derive class')

    def get_mib_data_sync(self, device_id):
        """
        Get the MIB Data Sync value last saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        raise NotImplementedError('Implement this in your derive class')

    def save_last_sync(self, device_id, value):
        """
        Save the Last Sync time to the database in an easy location to access

        :param device_id: (str) ONU Device ID
        :param value: (DateTime) Value to save
        """
        raise NotImplementedError('Implement this in your derive class')

    def get_last_sync(self, device_id):
        """
        Get the Last SYnc Time saved to the database for a device

        :param device_id: (str) ONU Device ID
        :return: (int) The Value or None if not found
        """
        raise NotImplementedError('Implement this in your derive class')

    def update_supported_managed_entities(self, device_id, managed_entities):
        """
        Update the supported OMCI Managed Entities for this device

        :param device_id: (str) ONU Device ID
        :param managed_entities: (set) Managed Entity class IDs
        """
        raise NotImplementedError('Implement this in your derive class')

    def update_supported_message_types(self, device_id, msg_types):
        """
        Update the supported OMCI Managed Entities for this device

        :param device_id: (str) ONU Device ID
        :param msg_types: (set) Message Type values (ints)
        """
        raise NotImplementedError('Implement this in your derive class')
