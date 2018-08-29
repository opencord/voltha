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
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure, returnValue
from twisted.internet import reactor
from common.utils.asleep import asleep
from voltha.extensions.omci.database.mib_db_dict import *
from voltha.extensions.omci.omci_entities import OntData
from voltha.extensions.omci.omci_defs import AttributeAccess
AA = AttributeAccess


class AlarmCopyException(Exception):
    pass


class AlarmDownloadException(Exception):
    pass


class AlarmResyncException(Exception):
    pass


class AlarmResyncTask(Task):
    """
    OpenOMCI ALARM resynchronization Task

    This task should get a copy of the ALARM and compare compare it to a
    copy of the database. When the ALARM Upload command is sent to the ONU,
    it should make a copy and source the data requested from this database.
    The ONU can still source AVC's and the the OLT can still send config
    commands to the actual.
    """
    task_priority = 240
    name = "ALARM Resynchronization Task"

    max_retries = 3
    retry_delay = 7

    max_alarm_upload_next_retries = 3
    alarm_upload_next_delay = 10          # Max * delay < 60 seconds
    watchdog_timeout = 15                 # Should be > any retry delay

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(AlarmResyncTask, self).__init__(AlarmResyncTask.name,
                                              omci_agent,
                                              device_id,
                                              priority=AlarmResyncTask.task_priority,
                                              exclusive=False,
                                              watchdog_timeout=AlarmResyncTask.watchdog_timeout)
        self._local_deferred = None
        self._device = omci_agent.get_device(device_id)
        self._db_active = MibDbVolatileDict(omci_agent)
        self._db_active.start()

    def cancel_deferred(self):
        super(AlarmResyncTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start ALARM Re-Synchronization task
        """
        super(AlarmResyncTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_alarm_resync)
        self._db_active.start()
        self._db_active.add(self.device_id)

    def stop(self):
        """
        Shutdown ALARM Re-Synchronization task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        self._db_active.stop()
        self._db_active = None
        super(AlarmResyncTask, self).stop()

    @inlineCallbacks
    def perform_alarm_resync(self):
        """
        Perform the ALARM Resynchronization sequence

        The sequence to be performed is:
            - get a copy of the current ALARM database

            - perform ALARM upload commands to get ONU's database and save this
              to a local DB.
        During the alarm upload process, the maximum time between alarm upload next
        requests is 1 minute.
        """
        self.log.info('perform-alarm-resync')

        try:
            self.strobe_watchdog()
            command_sequence_number = yield self.snapshot_alarm()

            # Start the ALARM upload sequence, save alarms to the table
            self.strobe_watchdog()
            commands_retrieved, alarm_table = yield self.upload_alarm(command_sequence_number)

            if commands_retrieved < command_sequence_number:
                e = AlarmDownloadException('Only retrieved {} of {} instances'.
                                             format(commands_retrieved, command_sequence_number))
                self.deferred.errback(failure.Failure(e))

            self.deferred.callback(
                    {
                        'commands_retrieved': commands_retrieved,
                        'alarm_table': alarm_table
                    })

        except Exception as e:
            self.log.exception('resync', e=e)
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def snapshot_alarm(self):
        """
        Snapshot the ALARM on the ONU and create a copy of our local ALARM database

        :return: (pair) (command_sequence_number)
        """
        command_sequence_number = None

        try:
            max_tries = AlarmResyncTask.max_retries - 1

            for retries in xrange(0, max_tries + 1):
                # Send ALARM Upload so ONU snapshots its ALARM
                try:
                    command_sequence_number = yield self.send_alarm_upload()
                    self.strobe_watchdog()

                    if command_sequence_number is None:
                        if retries >= max_tries:
                            break

                except TimeoutError as e:
                    self.log.warn('timeout', e=e)
                    if retries >= max_tries:
                        raise

                    self.strobe_watchdog()
                    yield asleep(AlarmResyncTask.retry_delay)
                    continue

        except Exception as e:
            self.log.exception('alarm-resync', e=e)
            raise

        # Handle initial failures

        if command_sequence_number is None:
            raise AlarmCopyException('Failed to snapshot ALARM copy after {} retries'.
                                     format(AlarmResyncTask.max_retries))

        returnValue(command_sequence_number)

    @inlineCallbacks
    def send_alarm_upload(self):
        """
        Perform ALARM upload command and get the number of entries to retrieve

        :return: (int) Number of commands to execute or None on error
        """
        ########################################
        # Begin ALARM Upload
        try:
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send_get_all_alarm()

            command_sequence_number = results.fields['omci_message'].fields['number_of_commands']

            if command_sequence_number is None or command_sequence_number <= 0:
                raise ValueError('Number of commands was {}'.format(command_sequence_number))

            returnValue(command_sequence_number)

        except TimeoutError as e:
            self.log.warn('alarm-resync-get-timeout', e=e)
            raise

    @inlineCallbacks
    def upload_alarm(self, command_sequence_number):
        ########################################
        # Begin ALARM Upload
        seq_no = None

        for seq_no in xrange(command_sequence_number):
            max_tries = AlarmResyncTask.max_alarm_upload_next_retries
            alarm_class_id = {}
            alarm_entity_id = {}
            attributes = {}

            for retries in xrange(0, max_tries):
                try:
                    self.strobe_watchdog()
                    response = yield self._device.omci_cc.get_all_alarm_next(seq_no)

                    omci_msg = response.fields['omci_message'].fields
                    alarm_class_id[seq_no] = omci_msg['alarmed_entity_class']
                    alarm_entity_id[seq_no] = omci_msg['alarmed_entity_id']

                    # Filter out the 'alarm_data_sync' from the database. We save that at
                    # the device level and do not want it showing up during a re-sync
                    # during data comparison

                    if alarm_class_id[seq_no] == OntData.class_id:
                        break

                    attributes[seq_no] = omci_msg['alarm_bit_map']

                    # Save to the database
                    self._db_active.set(self.device_id, alarm_class_id[seq_no],
                                        alarm_entity_id[seq_no], attributes[seq_no])
                    break

                except TimeoutError:
                    self.log.warn('alarm-resync-timeout', seq_no=seq_no,
                                  command_sequence_number=command_sequence_number)

                    if retries < max_tries - 1:
                        self.strobe_watchdog()
                        yield asleep(AlarmResyncTask.alarm_upload_next_delay)
                    else:
                        raise

                except Exception as e:
                    self.log.exception('resync', e=e, seq_no=seq_no,
                                       command_sequence_number=command_sequence_number)

        self.strobe_watchdog()
        returnValue((seq_no + 1, alarm_class_id, alarm_entity_id, attributes))     # seq_no is zero based and alarm table.

