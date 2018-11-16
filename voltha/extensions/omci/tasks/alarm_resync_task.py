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
from voltha.extensions.omci.omci_defs import AttributeAccess
from voltha.extensions.omci.database.alarm_db_ext import AlarmDbExternal

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
    task_priority = Task.DEFAULT_PRIORITY
    name = "ALARM Resynchronization Task"

    max_retries = 3
    retry_delay = 7

    max_alarm_upload_next_retries = 3
    alarm_upload_next_delay = 10          # Max * delay < 60 seconds

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
                                              exclusive=False)
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
        self.log.debug('perform-alarm-resync')

        try:
            self.strobe_watchdog()
            results = yield self.snapshot_alarm()
            olt_db_copy = results[0]
            number_of_commands = results[1]

            if olt_db_copy is None:
                e = AlarmCopyException('Failed to get local database copy')
                self.deferred.errback(failure.Failure(e))
            else:
                # Start the ALARM upload sequence, save alarms to the table
                self.strobe_watchdog()

                if number_of_commands > 0:
                    commands_retrieved = yield self.upload_alarm(number_of_commands)
                else:
                    commands_retrieved = 0

                if commands_retrieved != number_of_commands:
                    e = AlarmDownloadException('Only retrieved {} of {} instances'.
                                               format(commands_retrieved, number_of_commands))
                    self.deferred.errback(failure.Failure(e))
                else:
                    # Compare the databases
                    onu_db_copy = self._db_active.query(self.device_id)

                    on_olt_only, on_onu_only, attr_diffs = \
                        self.compare_mibs(olt_db_copy, onu_db_copy)

                    on_olt_only = on_olt_only if len(on_olt_only) else None
                    on_onu_only = on_onu_only if len(on_onu_only) else None
                    attr_diffs = attr_diffs if len(attr_diffs) else None

                    on_olt_only_diffs = on_olt_only if on_olt_only and len(on_olt_only) else None
                    on_onu_only_diffs = on_onu_only if on_onu_only and len(on_onu_only) else None
                    attr_diffs = attr_diffs if attr_diffs and len(attr_diffs) else None

                    if all(diff is None for diff in [on_olt_only_diffs, on_onu_only_diffs, attr_diffs]):
                        results = None
                    else:
                        results = {
                            'onu-only': on_onu_only_diffs,
                            'olt-only': on_olt_only_diffs,
                            'attr-diffs': attr_diffs,
                            'onu-db': onu_db_copy,
                            'olt-db': olt_db_copy
                        }
                    self.deferred.callback(results)

        except Exception as e:
            self.log.exception('resync', e=e)
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def snapshot_alarm(self):
        """
        Snapshot the ALARM on the ONU and create a copy of our local ALARM database

        :return: (pair) (command_sequence_number)
        """
        olt_db_copy = None
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
                            olt_db_copy = None
                            break

                except TimeoutError as e:
                    self.log.warn('timeout', e=e)
                    if retries >= max_tries:
                        raise

                    self.strobe_watchdog()
                    yield asleep(AlarmResyncTask.retry_delay)
                    continue

                # Get a snapshot of the local MIB database
                olt_db_copy = self._device.query_alarm_table()
                # if we made it this far, no need to keep trying
                break

        except Exception as e:
            self.log.exception('alarm-resync', e=e)
            raise

        # Handle initial failures

        if olt_db_copy is None or command_sequence_number is None:
            raise AlarmCopyException('Failed to snapshot ALARM copy after {} retries'.
                                     format(AlarmResyncTask.max_retries))

        returnValue((olt_db_copy, command_sequence_number))

    @inlineCallbacks
    def send_alarm_upload(self):
        """
        Perform ALARM upload command and get the number of entries to retrieve

        :return: (int) Number of commands to execute or None on error
        """
        ########################################
        # Begin ALARM Upload
        try:
            results = yield self._device.omci_cc.send_get_all_alarm()
            self.strobe_watchdog()
            command_sequence_number = results.fields['omci_message'].fields['number_of_commands']

            if command_sequence_number < 0:
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

            for retries in xrange(0, max_tries):
                try:
                    response = yield self._device.omci_cc.send_get_all_alarm_next(seq_no)
                    self.strobe_watchdog()

                    omci_msg = response.fields['omci_message'].fields
                    alarm_class_id = omci_msg['alarmed_entity_class']
                    alarm_entity_id = omci_msg['alarmed_entity_id']

                    alarm_bit_map = omci_msg['alarm_bit_map']
                    attributes = {AlarmDbExternal.ALARM_BITMAP_KEY: alarm_bit_map}

                    # Save to the database
                    self._db_active.set(self.device_id, alarm_class_id,
                                        alarm_entity_id, attributes)
                    break

                except TimeoutError:
                    self.log.warn('alarm-resync-timeout', seq_no=seq_no,
                                  command_sequence_number=command_sequence_number)

                    if retries < max_tries - 1:
                        yield asleep(AlarmResyncTask.alarm_upload_next_delay)
                        self.strobe_watchdog()
                    else:
                        raise

                except Exception as e:
                    self.log.exception('resync', e=e, seq_no=seq_no,
                                       command_sequence_number=command_sequence_number)

        returnValue(seq_no + 1)     # seq_no is zero based and alarm table.

    def compare_mibs(self, db_copy, db_active):
        """
        Compare the our db_copy with the ONU's active copy

        :param db_copy: (dict) OpenOMCI's copy of the database
        :param db_active: (dict) ONU's database snapshot
        :return: (dict), (dict), dict()  Differences
        """
        self.strobe_watchdog()

        # Class & Entities only in local copy (OpenOMCI)
        on_olt_only = self.get_lsh_only_dict(db_copy, db_active)

        # Class & Entities only on remote (ONU)
        on_onu_only = self.get_lsh_only_dict(db_active, db_copy)

        # Class & Entities on both local & remote, but one or more attributes
        # are different on the ONU.  This is the value that the local (OpenOMCI)
        # thinks should be on the remote (ONU)

        me_map = self.omci_agent.get_device(self.device_id).me_map
        attr_diffs = self.get_attribute_diffs(db_copy, db_active, me_map)

        return on_olt_only, on_onu_only, attr_diffs

    def get_lsh_only_dict(self, lhs, rhs):
        """
        Compare two MIB database dictionaries and return the ME Class ID and
        instances that are unique to the lhs dictionary. Both parameters
        should be in the common MIB Database output dictionary format that
        is returned by the mib 'query' command.

        :param lhs: (dict) Left-hand-side argument.
        :param rhs: (dict) Right-hand-side argument

        return: (list(int,int)) List of tuples where (class_id, inst_id)
        """
        results = list()

        for cls_id, cls_data in lhs.items():
            # Get unique classes
            #
            # Skip keys that are not class IDs
            if not isinstance(cls_id, int):
                continue

            if cls_id not in rhs:
                results.extend([(cls_id, inst_id) for inst_id in cls_data.keys()
                                if isinstance(inst_id, int)])
            else:
                # Get unique instances of a class
                lhs_cls = cls_data
                rhs_cls = rhs[cls_id]

                for inst_id, _ in lhs_cls.items():
                    # Skip keys that are not instance IDs
                    if isinstance(cls_id, int) and inst_id not in rhs_cls:
                        results.extend([(cls_id, inst_id)])

        return results

    def get_attribute_diffs(self, omci_copy, onu_copy, me_map):
        """
        Compare two OMCI MIBs and return the ME class and instance IDs that exists
        on both the local copy and the remote ONU that have different attribute
        values. Both parameters should be in the common MIB Database output
        dictionary format that is returned by the mib 'query' command.

        :param omci_copy: (dict) OpenOMCI copy (OLT-side) of the MIB Database
        :param onu_copy: (dict) active ONU latest copy its database
        :param me_map: (dict) ME Class ID MAP for this ONU

        return: (list(int,int,str)) List of tuples where (class_id, inst_id, attribute)
                                    points to the specific ME instance where attributes
                                    are different
        """
        results = list()

        # Get class ID's that are in both
        class_ids = {cls_id for cls_id, _ in omci_copy.items()
                     if isinstance(cls_id, int) and cls_id in onu_copy}

        for cls_id in class_ids:
            # Get unique instances of a class
            olt_cls = omci_copy[cls_id]
            onu_cls = onu_copy[cls_id]

            # Get set of common instance IDs
            inst_ids = {inst_id for inst_id, _ in olt_cls.items()
                        if isinstance(inst_id, int) and inst_id in onu_cls}

            for inst_id in inst_ids:
                omci_attributes = {k for k in olt_cls[inst_id][ATTRIBUTES_KEY].iterkeys()}
                onu_attributes = {k for k in onu_cls[inst_id][ATTRIBUTES_KEY].iterkeys()}

                # Get attributes that exist in one database, but not the other
                sym_diffs = (omci_attributes ^ onu_attributes)
                results.extend([(cls_id, inst_id, attr) for attr in sym_diffs])

                # Get common attributes with different values
                common_attributes = (omci_attributes & onu_attributes)
                results.extend([(cls_id, inst_id, attr) for attr in common_attributes
                               if olt_cls[inst_id][ATTRIBUTES_KEY][attr] !=
                                onu_cls[inst_id][ATTRIBUTES_KEY][attr]])
        return results
