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
from task import Task
from datetime import datetime
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure, returnValue
from twisted.internet import reactor
from common.utils.asleep import asleep
from voltha.extensions.omci.database.mib_db_dict import *
from voltha.extensions.omci.omci_defs import ReasonCodes
from voltha.extensions.omci.omci_entities import OntData


class MibCopyException(Exception):
    pass


class MibDownloadException(Exception):
    pass


class MibResyncTask(Task):
    """
    OpenOMCI MIB resynchronization Task

    This task should get a copy of the MIB and compare compare it to a
    copy of the database. When the MIB Upload command is sent to the ONU,
    it should make a copy and source the data requested from this database.
    The ONU can still source AVC's and the the OLT can still send config
    commands to the actual.
    """
    task_priority = 240
    name = "MIB Resynchronization Task"

    max_db_copy_retries = 3
    db_copy_retry_delay = 7

    max_mib_upload_next_retries = 3
    mib_upload_next_delay = 10          # Max * delay < 60 seconds

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(MibResyncTask, self).__init__(MibResyncTask.name,
                                            omci_agent,
                                            device_id,
                                            priority=MibResyncTask.task_priority)
        self._local_deferred = None
        self._device = omci_agent.get_device(device_id)
        self._db_active = MibDbVolatileDict(omci_agent)
        self._db_active.add(device_id)

    def cancel_deferred(self):
        super(MibResyncTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start MIB Synchronization tasks
        """
        super(MibResyncTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_mib_resync)
        self._db_active.start()

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        self._db_active.stop()
        super(MibResyncTask, self).stop()

    @inlineCallbacks
    def perform_mib_resync(self):
        """
        Perform the MIB Resynchronization sequence

        The sequence to be performed are:
            - get a copy of the current MIB database (db_copy)

            - perform MIB upload commands to get ONU's database and save this
              to a local DB (db_active). Note that the ONU can still receive
              create/delete/set/get operations from the operator and source
              AVC notifications as well during this period.

            - Compare the information in the db_copy to the db_active

        During the mib upload process, the maximum time between mib upload next
        requests is 1 minute.
        """
        self.log.info('perform-mib-resync')

        # Try at least 3 times to snapshot the current MIB and get the
        # MIB upload request out so ONU snapshots its database

        db_copy = None
        number_of_commands = None
        commands_retrieved = 0

        try:
            results = yield self.snapshot_mib()
            db_copy = results[0]
            number_of_commands = results[1]

            # Start the MIB upload sequence
            commands_retrieved = yield self.upload_mib(number_of_commands)

        except Exception as e:
            self.deferred.errback(failure.Failure(e))
            returnValue(None)

        if db_copy is None:
            e = MibCopyException('Failed to get local database copy')
            self.deferred.errback(failure.Failure(e))
            returnValue('FAILED')

        if commands_retrieved < number_of_commands:
            e = MibDownloadException('Only retrieved {} of {} instances'.
                                     format(commands_retrieved, number_of_commands))
            self.deferred.errback(failure.Failure(e))
            returnValue('FAILED')

        # Compare the database

        mib_differences = self.compare_mibs(db_copy,
                                            self._db_active.query(self.device_id))

        if mib_differences is None:
            self.deferred.callback('success')
            self.deferred.callback('TODO: This task has not been coded.')

        # TODO: Handle mismatches
        pass

    @inlineCallbacks
    def snapshot_mib(self):
        """
        Snapshot the MIB on the ONU and create a copy of our local MIB database

        :return: (pair) (db_copy, number_of_commands)
        """
        db_copy = None
        number_of_commands = None

        try:
            max_tries = MibResyncTask.max_db_copy_retries - 1

            for retries in xrange(0, max_tries + 1):
                # Send MIB Upload so ONU snapshots its MIB
                try:
                    mib_upload_time = datetime.utcnow()
                    number_of_commands = yield self.send_mib_upload()

                    if number_of_commands is None:
                        if retries >= max_tries:
                            break

                except TimeoutError as e:
                    self.log.warn('timeout', e=e)
                    if retries >= max_tries:
                        raise

                    yield asleep(MibResyncTask.db_copy_retry_delay)
                    continue

                # Get a snapshot of the local MIB database
                db_copy = self._device.query_mib()

                if db_copy is None or db_copy[MODIFIED_KEY] > mib_upload_time:
                    if retries >= max_tries:
                        break

                    yield asleep(MibResyncTask.db_copy_retry_delay)
                    continue
                break

        except Exception as e:
            self.log.exception('mib-resync', e=e)
            raise

        # Handle initial failures

        if db_copy is None or number_of_commands is None:
            raise MibCopyException('Failed to snapshot MIB copy after {} retries'.
                                   format(MibResyncTask.max_db_copy_retries))

        returnValue((db_copy, number_of_commands))

    @inlineCallbacks
    def send_mib_upload(self):
        """
        Perform MIB upload command and get the number of entries to retrieve

        :return: (int) Number of commands to execute or None on error
        """
        ########################################
        # Begin MIB Upload
        try:
            results = yield self._device.omci_cc.send_mib_upload()
            number_of_commands = results.fields['omci_message'].fields['number_of_commands']

            if number_of_commands is None or number_of_commands <= 0:
                raise ValueError('Number of commands was {}'.format(number_of_commands))

            returnValue(number_of_commands)

        except TimeoutError as e:
            self.log.warn('mib-resync-get-timeout', e=e)
            raise

    @inlineCallbacks
    def upload_mib(self, number_of_commands):
        ########################################
        # Begin MIB Upload

        seq_no = None

        for seq_no in xrange(number_of_commands):
            max_tries = MibResyncTask.max_mib_upload_next_retries - 1

            for retries in xrange(0, max_tries + 1):
                try:
                    response = yield self._device.omci_cc.send_mib_upload_next(seq_no)

                    omci_msg = response.fields['omci_message'].fields
                    class_id = omci_msg['object_entity_class']
                    entity_id = omci_msg['object_entity_id']

                    # Filter out the 'mib_data_sync' from the database. We save that at
                    # the device level and do not want it showing up during a re-sync
                    # during data compares

                    if class_id == OntData.class_id:
                        pass      # TODO: Save to a local variable

                    attributes = {k: v for k, v in omci_msg['object_data'].items()}

                    # Save to the database
                    self._db_active.set(self.device_id, class_id, entity_id, attributes)

                except TimeoutError as e:
                    self.log.warn('mib-resync-timeout', e=e, seq_no=seq_no,
                                  number_of_commands=number_of_commands)
                    if retries >= max_tries:
                        raise

                    yield asleep(MibResyncTask.mib_upload_next_delay)
                    continue

        returnValue(seq_no)

    def compare_mibs(self, db_copy, db_active):
        """
        Compare the our db_copy with the ONU's active copy
        :param db_copy: (dict) OpenOMCI's copy of the database
        :param db_active: (dict) ONU's database snapshot
        :return: (dict) Difference dictionary
        """
        return None        # TODO: Do this
        # TODO: Note that certain MEs are excluded from the MIB upload.  In particular,
        #       instances of some gneeral purpose MEs, such as the Managed Entity ME and
        #       and the Attribute ME are not included in the MIB upload.  Also all table
        #       attributes are not included in the MIB upload (but we do not yet support
        #       tables in this OpenOMCI implementation (VOLTHA v1.3.0)
