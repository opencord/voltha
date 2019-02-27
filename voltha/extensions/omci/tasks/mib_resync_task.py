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
from voltha.extensions.omci.omci_entities import OntData, Omci
from voltha.extensions.omci.omci_defs import AttributeAccess, EntityOperations
from voltha.extensions.omci.omci_fields import OmciTableField
from voltha.extensions.omci.omci_me import OntDataFrame

AA = AttributeAccess
OP = EntityOperations


class MibCopyException(Exception):
    pass


class MibDownloadException(Exception):
    pass


class MibResyncException(Exception):
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
    watchdog_timeout = 15               # Should be > max delay

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(MibResyncTask, self).__init__(MibResyncTask.name,
                                            omci_agent,
                                            device_id,
                                            priority=MibResyncTask.task_priority,
                                            exclusive=False)
        self._local_deferred = None
        self._device = omci_agent.get_device(device_id)
        self._db_active = MibDbVolatileDict(omci_agent)
        self._db_active.start()

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
        Start MIB Re-Synchronization task
        """
        super(MibResyncTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_mib_resync)
        self._db_active.start()
        self._db_active.add(self.device_id)

    def stop(self):
        """
        Shutdown MIB Re-Synchronization task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        self._db_active.stop()
        self._db_active = None
        super(MibResyncTask, self).stop()

    @inlineCallbacks
    def perform_mib_resync(self):
        """
        Perform the MIB Resynchronization sequence

        The sequence to be performed is:
            - get a copy of the current MIB database (db_copy)

            - perform MIB upload commands to get ONU's database and save this
              to a local DB (db_active). Note that the ONU can still receive
              create/delete/set/get operations from the operator and source
              AVC notifications as well during this period.

            - Compare the information in the db_copy to the db_active

        During the mib upload process, the maximum time between mib upload next
        requests is 1 minute.
        """
        self.log.debug('perform-mib-resync')

        try:
            results = yield self.snapshot_mib()
            db_copy = results[0]

            if db_copy is None:
                e = MibCopyException('Failed to get local database copy')
                self.deferred.errback(failure.Failure(e))

            else:
                number_of_commands = results[1]

                # Start the MIB upload sequence
                self.strobe_watchdog()
                commands_retrieved = yield self.upload_mib(number_of_commands)

                if commands_retrieved < number_of_commands:
                    e = MibDownloadException('Only retrieved {} of {} instances'.
                                             format(commands_retrieved, number_of_commands))
                    self.deferred.errback(failure.Failure(e))
                else:
                    # Compare the databases
                    active_copy = self._db_active.query(self.device_id)
                    on_olt_only, on_onu_only, attr_diffs = \
                        self.compare_mibs(db_copy, active_copy)

                    self.deferred.callback(
                            {
                                'on-olt-only': on_olt_only if len(on_olt_only) else None,
                                'on-onu-only': on_onu_only if len(on_onu_only) else None,
                                'attr-diffs': attr_diffs if len(attr_diffs) else None,
                                'olt-db': db_copy,
                                'onu-db': active_copy
                            })

        except Exception as e:
            self.log.exception('resync', e=e)
            self.deferred.errback(failure.Failure(e))

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
                    self.strobe_watchdog()
                    number_of_commands = yield self.send_mib_upload()

                    if number_of_commands is None:
                        if retries >= max_tries:
                            db_copy = None
                            break

                except (TimeoutError, ValueError) as e:
                    self.log.warn('timeout-or-value-error', e=e)
                    if retries >= max_tries:
                        raise

                    self.strobe_watchdog()
                    yield asleep(MibResyncTask.db_copy_retry_delay)
                    continue

                # Get a snapshot of the local MIB database
                db_copy = self._device.query_mib()
                # if we made it this far, no need to keep trying
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
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send_mib_upload()

            number_of_commands = results.fields['omci_message'].fields['number_of_commands']

            if number_of_commands is None or number_of_commands <= 0:
                raise ValueError('Number of commands was {}'.format(number_of_commands))

            # Get the current MIB-DATA-SYNC on the ONU
            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(OntDataFrame().get())
            omci_msg = results.fields['omci_message'].fields
            mds = (omci_msg['data']['mib_data_sync'] >> 8) & 0xFF
            self._db_active.save_mib_data_sync(self.device_id, mds)

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
            max_tries = MibResyncTask.max_mib_upload_next_retries

            for retries in xrange(0, max_tries):
                try:
                    self.strobe_watchdog()
                    response = yield self._device.omci_cc.send_mib_upload_next(seq_no)

                    omci_msg = response.fields['omci_message'].fields
                    class_id = omci_msg['object_entity_class']
                    entity_id = omci_msg['object_entity_id']

                    # Filter out the 'mib_data_sync' from the database. We save that at
                    # the device level and do not want it showing up during a re-sync
                    # during data comparison
                    from binascii import hexlify
                    if class_id in (OntData.class_id, Omci.class_id):
                        break

                    # The T&W ONU reports an ME with class ID 0 but only on audit. Perhaps others do as well.
                    if class_id == 0 or class_id > 0xFFFF:
                        self.log.warn('invalid-class-id', class_id=class_id)
                        break

                    attributes = {k: v for k, v in omci_msg['object_data'].items()}

                    # Save to the database
                    self._db_active.set(self.device_id, class_id, entity_id, attributes)
                    break

                except TimeoutError:
                    self.log.warn('mib-resync-timeout', seq_no=seq_no,
                                  number_of_commands=number_of_commands)

                    if retries < max_tries - 1:
                        self.strobe_watchdog()
                        yield asleep(MibResyncTask.mib_upload_next_delay)
                    else:
                        raise

                except Exception as e:
                    self.log.exception('resync', e=e, seq_no=seq_no,
                                       number_of_commands=number_of_commands)

        returnValue(seq_no + 1)     # seq_no is zero based.

    def compare_mibs(self, db_copy, db_active):
        """
        Compare the our db_copy with the ONU's active copy

        :param db_copy: (dict) OpenOMCI's copy of the database
        :param db_active: (dict) ONU's database snapshot
        :return: (dict), (dict), (list)  Differences
        """
        self.strobe_watchdog()
        me_map = self.omci_agent.get_device(self.device_id).me_map

        # Class & Entities only in local copy (OpenOMCI)
        on_olt_temp = self.get_lhs_only_dict(db_copy, db_active)

        # Remove any entries that are not reported during an upload (but could
        # be in our database copy. Retain undecodable class IDs.
        on_olt_only = [(cid, eid) for cid, eid in on_olt_temp
                       if cid not in me_map or not me_map[cid].hidden]

        # Further reduce the on_olt_only MEs reported in an audit to not
        # include missed MEs that are ONU created. Not all ONUs report MEs
        # that are ONU created unless we are doing the initial MIB upload.
        # Adtran does report them, T&W may not as well as a few others
        on_olt_only = [(cid, eid) for cid, eid in on_olt_only if cid in me_map and
                       (OP.Create in me_map[cid].mandatory_operations or
                        OP.Create in me_map[cid].optional_operations)]

        # Class & Entities only on remote (ONU)
        on_onu_only = self.get_lhs_only_dict(db_active, db_copy)

        # Class & Entities on both local & remote, but one or more attributes
        # are different on the ONU.  This is the value that the local (OpenOMCI)
        # thinks should be on the remote (ONU)

        attr_diffs = self.get_attribute_diffs(db_copy, db_active, me_map)

        # TODO: Note that certain MEs are excluded from the MIB upload.  In particular,
        #       instances of some general purpose MEs, such as the Managed Entity ME and
        #       and the Attribute ME are not included in the MIB upload.  Also all table
        #       attributes are not included in the MIB upload (but we do not yet support
        #       tables in this OpenOMCI implementation (VOLTHA v1.3.0)

        return on_olt_only, on_onu_only, attr_diffs

    def get_lhs_only_dict(self, lhs, rhs):
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
        ro_set = {AA.R}

        # Get class ID's that are in both
        class_ids = {cls_id for cls_id, _ in omci_copy.items()
                     if isinstance(cls_id, int) and cls_id in onu_copy}

        for cls_id in class_ids:
            # Get unique instances of a class
            olt_cls = omci_copy[cls_id]
            onu_cls = onu_copy[cls_id]

            # Weed out read-only and table attributes. Attributes on onu may be read-only.
            # These will only show up it the OpenOMCI (OLT-side) database if it changed
            # and an AVC Notification was sourced by the ONU
            # TODO: These class IDs could be calculated once at ONU startup (at device add)
            if cls_id in me_map:
                ro_attrs = {attr.field.name for attr in me_map[cls_id].attributes
                            if attr.access == ro_set}
                table_attrs = {attr.field.name for attr in me_map[cls_id].attributes
                               if isinstance(attr.field, OmciTableField)}

            else:
                # Here if partially defined ME (not defined in ME Map)
                from voltha.extensions.omci.omci_cc import UNKNOWN_CLASS_ATTRIBUTE_KEY
                ro_attrs = {UNKNOWN_CLASS_ATTRIBUTE_KEY}

            # Get set of common instance IDs
            inst_ids = {inst_id for inst_id, _ in olt_cls.items()
                        if isinstance(inst_id, int) and inst_id in onu_cls}

            for inst_id in inst_ids:
                omci_attributes = {k for k in olt_cls[inst_id][ATTRIBUTES_KEY].iterkeys()}
                onu_attributes = {k for k in onu_cls[inst_id][ATTRIBUTES_KEY].iterkeys()}

                # Get attributes that exist in one database, but not the other
                sym_diffs = (omci_attributes ^ onu_attributes) - ro_attrs - table_attrs
                results.extend([(cls_id, inst_id, attr) for attr in sym_diffs])

                # Get common attributes with different values
                common_attributes = (omci_attributes & onu_attributes) - ro_attrs - table_attrs
                results.extend([(cls_id, inst_id, attr) for attr in common_attributes
                               if olt_cls[inst_id][ATTRIBUTES_KEY][attr] !=
                                onu_cls[inst_id][ATTRIBUTES_KEY][attr]])
        return results
