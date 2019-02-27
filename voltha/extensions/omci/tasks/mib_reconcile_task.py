#
# Copyright 2018 the original author or authors.
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

from common.utils.asleep import asleep
from voltha.extensions.omci.tasks.task import Task
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, failure, returnValue, TimeoutError
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_me import OntDataFrame
from voltha.extensions.omci.omci_frame import OmciFrame, OmciDelete, OmciCreate, OmciSet
from voltha.extensions.omci.database.mib_db_api import ATTRIBUTES_KEY

OP = EntityOperations
RC = ReasonCodes
AA = AttributeAccess


class MibReconcileException(Exception):
    pass


class MibPartialSuccessException(Exception):
    pass


class MibReconcileTask(Task):
    """
    OpenOMCI MIB Reconcile Task

    This task attempts to resynchronize the MIB. Note that it runs in exclusive
    OMCI-CC mode so that it can query the current database/ONU to verify the
    differences still exist before correcting them.
    """
    task_priority = 240
    name = "MIB Reconcile Task"
    max_sequential_db_updates = 5   # Be kind, rewind
    db_update_pause = 0.05          # 50mS

    def __init__(self, omci_agent, device_id, diffs):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param diffs: (dict) Dictionary of what was found to be invalid
        """
        super(MibReconcileTask, self).__init__(MibReconcileTask.name,
                                               omci_agent,
                                               device_id,
                                               priority=MibReconcileTask.task_priority,
                                               exclusive=False)
        self._local_deferred = None
        self._diffs = diffs
        self._device = None
        self._sync_sm = None
        self._db_updates = 0    # For tracking sequential blocking consul/etcd updates

    def cancel_deferred(self):
        super(MibReconcileTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start MIB Reconcile task
        """
        super(MibReconcileTask, self).start()

        self._device = self.omci_agent.get_device(self.device_id)

        if self._device is None:
            e = MibReconcileException('Device {} no longer exists'.format(self.device_id))
            self.deferred.errback(failure.Failure(e))
            return

        self._sync_sm = self._device.mib_synchronizer

        if self._device is None:
            e = MibReconcileException('Device {} MIB State machine no longer exists'.format(self.device_id))
            self.deferred.errback(failure.Failure(e))
            return

        self._local_deferred = reactor.callLater(0, self.perform_mib_reconcile)

    def stop(self):
        """
        Shutdown MIB Reconcile task
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        self._device = None
        super(MibReconcileTask, self).stop()

    @inlineCallbacks
    def perform_mib_reconcile(self):
        """
        Perform the MIB Reconciliation sequence.

        The sequence to reconcile will be to clean up ONU only MEs, followed by
        OLT/OpenOMCI-only MEs, and then finally correct common MEs with differing
        attributes.
        """
        self.log.debug('perform-mib-reconcile')

        try:
            successes = 0
            failures = 0

            if self._diffs['onu-only'] is not None and len(self._diffs['onu-only']):
                results = yield self.fix_onu_only(self._diffs['onu-only'],
                                                  self._diffs['onu-db'])
                self.log.debug('onu-only-results', good=results[0], bad=results[1])
                successes += results[0]
                failures += results[1]

            if self._diffs['olt-only'] is not None and len(self._diffs['olt-only']):
                results = yield self.fix_olt_only(self._diffs['olt-only'],
                                                  self._diffs['onu-db'],
                                                  self._diffs['olt-db'])
                self.log.debug('olt-only-results', good=results[0], bad=results[1])
                successes += results[0]
                failures += results[1]

            if self._diffs['attributes'] is not None and len(self._diffs['attributes']):
                results = yield self.fix_attributes_only(self._diffs['attributes'],
                                                         self._diffs['onu-db'],
                                                         self._diffs['olt-db'])
                self.log.debug('attributes-results', good=results[0], bad=results[1])
                successes += results[0]
                failures += results[1]

            # Success? Update MIB-data-sync
            if failures == 0:
                results = yield self.update_mib_data_sync()
                successes += results[0]
                failures += results[1]

            # Send back final status
            if failures > 0:
                msg = '{} Successful updates, {} failures'.format(successes, failure)
                error = MibPartialSuccessException(msg) if successes \
                    else MibReconcileException(msg)
                self.deferred.errback(failure.Failure(error))
            else:
                self.deferred.callback('{} Successful updates'.format(successes))

        except Exception as e:
            if not self.deferred.called:
                self.log.exception('reconcile', e=e)
                self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def fix_onu_only(self, onu, onu_db):
        """
        Fix ME's that were only found on the ONU. For ONU only MEs there are
        the following things that will be checked.

            o ME's that do not have an OpenOMCI class decoder. These are stored
              as binary blobs in the MIB database. Since we do not ever set them
              (since no encoder as well), just store them in the OLT/OpenOMCI MIB
              Database.

            o For ME's that are created by the ONU (no create/delete access), the
              MEs 'may' be due to a firmware upgrade and reboot or in response to
              an OLT creating another ME entity and then creating this ME.  Place
              these 'new' into the database.

            o For ME's that are created by the OLT/OpenOMCI, delete them from the
              ONU

        :param onu: (list(int,int)) List of tuples where (class_id, inst_id)
        :param onu_db: (dict) ONU Database snapshot at time of audit

        :return: (int, int) successes, failures
        """
        successes = 0
        failures = 0
        me_map = self._device.me_map

        ####################################################################
        # First the undecodables and onu-created (treated the same)
        undecodable = self._undecodable(onu, me_map)
        onu_created = self._onu_created(onu, me_map)

        if len(undecodable) or len(onu_created):
            results = yield self.fix_onu_only_save_to_db(undecodable, onu_created, onu_db)
            successes += results[0]
            failures += results[1]

        ####################################################################
        # Last the OLT created values, resend these to the ONU

        olt_created = self._olt_created(onu, me_map)
        if len(olt_created):
            results = yield self.fix_onu_only_remove_from_onu(olt_created)
            successes += results[0]
            failures += results[1]

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_onu_only_save_to_db(self, undecodable, onu_created, onu_db):
        """
        In ONU database and needs to be saved to OLT/OpenOMCI database.

        Note that some, perhaps all, of these instances could be ONU create
        in response to the OLT creating some other ME instance. So treat
        the Database operation as a create.
        """
        successes = 0
        failures = 0

        for cid, eid in undecodable + onu_created:
            if self.deferred.called:        # Check if task canceled
                break
            try:
                # If in current MIB, had an audit issue or other MIB operation
                # put it into the database, declare it a failure so we audit again
                try:
                    olt_entry = self._sync_sm.query_mib(class_id=cid, instance_id=eid)

                except KeyError:        # Common for ONU created MEs during audit
                    olt_entry = None

                if olt_entry is not None and len(olt_entry):
                    self.log.debug('onu-only-in-current', cid=cid, eid=eid)
                    failures += 1     # Mark as failure so we audit again

                elif cid not in onu_db:
                    self.log.warn('onu-only-not-in-audit', cid=cid, eid=eid)
                    failures += 1

                else:
                    entry = onu_db[cid][eid]
                    self.strobe_watchdog()
                    self._sync_sm.mib_set(cid, eid, entry[ATTRIBUTES_KEY])
                    successes += 1

                    # If we do nothing but DB updates for ALOT of MEs, we are
                    # blocking other async twisted tasks, be kind and pause
                    self._db_updates += 1

                    if self._db_updates >= MibReconcileTask.max_sequential_db_updates:
                        self._db_updates = 0
                        self._local_deferred = yield asleep(MibReconcileTask.db_update_pause)

            except Exception as e:
                self.log.warn('onu-only-error', e=e)
                failures += 1

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_onu_only_remove_from_onu(self, olt_created,):
        """ On ONU, but no longer on OLT/OpenOMCI, delete it """
        successes = 0
        failures = 0

        for cid, eid in olt_created:
            if self.deferred.called:        # Check if task canceled
                break
            try:
                # If in current MIB, had an audit issue, declare it an error
                # and next audit should clear it up
                try:
                    current_entry = self._sync_sm.query_mib(class_id=cid, instance_id=eid)

                except KeyError:
                    # Expected if no other entities with same class present in MIB
                    current_entry = None

                if current_entry is not None and len(current_entry):
                    self.log.debug('onu-only-in-current', cid=cid, eid=eid)
                    failures += 1

                else:
                    # Delete it from the ONU. Assume success
                    frame = OmciFrame(transaction_id=None,
                                      message_type=OmciDelete.message_id,
                                      omci_message=OmciDelete(entity_class=cid, entity_id=eid))

                    self._local_deferred = yield self._device.omci_cc.send(frame)
                    self.check_status_and_state(self._local_deferred, 'onu-attribute-update')
                    successes += 1
                    self._db_updates = 0

            except Exception as e:
                self.log.warn('olt-only-error', e=e)
                failures += 1
                self.strobe_watchdog()

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_olt_only(self, olt, onu_db, olt_db):
        """
        Fix ME's that were only found on the OLT. For OLT only MEs there are
        the following things that will be checked.

            o ME's that do not have an OpenOMCI class decoder. These are stored
              as binary blobs in the MIB database. Since the OLT will never
              create these (all are learned from ONU), it is assumed the ONU
              has removed them for some purpose. So delete them from the OLT
              database.

            o For ME's that are created by the ONU (no create/delete access), the
              MEs 'may' not be on the ONU because of a reboot or an OLT created
              ME was deleted and the ONU gratuitously removes it.  So delete them
              from the OLT database.

            o For ME's that are created by the OLT/OpenOMCI, delete them from the
              ONU

        :param olt: (list(int,int)) List of tuples where (class_id, inst_id)
        :param onu_db: (dict) ONU Database snapshot at time of audit
        :param olt_db: (dict) OLT Database snapshot at time of audit

        :return: (int, int) successes, failures
        """
        successes = 0
        failures = 0
        me_map = self._device.me_map

        ####################################################################
        # First the undecodables and onu-created (treated the same) remove
        # from OpenOMCI database
        undecodable = self._undecodable(olt, me_map)
        onu_created = self._onu_created(olt, me_map)

        if len(undecodable) or len(onu_created):
            good, bad = self.fix_olt_only_remove_from_db(undecodable, onu_created)
            successes += good
            failures += bad

        ####################################################################
        # Last the OLT created

        olt_created = self._olt_created(olt, me_map)
        if len(olt_created):
            results = yield self.fix_olt_only_create_on_onu(olt_created, me_map)
            successes += results[0]
            failures += results[1]

        returnValue((successes, failures))

    def fix_olt_only_remove_from_db(self, undecodable, onu_created):
        """ On OLT, but not on ONU and are ONU created, delete from OLT/OpenOMCI DB """
        successes = 0
        failures = 0

        for cid, eid in undecodable + onu_created:
            if self.deferred.called:        # Check if task canceled
                break
            try:
                # Delete it. If already deleted (KeyError), then that is okay
                self._sync_sm.mib_delete(cid, eid)
                self.strobe_watchdog()

            except KeyError:
                successes += 1      # Not found in DB anymore, assume success

            except Exception as e:
                self.log.warn('olt-only-db-error', cid=cid, eid=eid, e=e)
                failures += 1

        return successes, failures

    @inlineCallbacks
    def fix_olt_only_create_on_onu(self, olt_created, me_map):
        """ Found on OLT and created by OLT, so create on ONU"""
        successes = 0
        failures = 0

        for cid, eid in olt_created:
            if self.deferred.called:        # Check if task canceled
                break

            try:
                # Get current entry, use it if found
                olt_entry = self._sync_sm.query_mib(class_id=cid, instance_id=eid)
                me_entry = me_map[cid]

                if olt_entry is None or len(olt_entry) == 0:
                    successes += 1      # Deleted before task got to run
                else:
                    # Create it in the ONU. Only set-by-create attributes allowed
                    sbc_data = {k: v for k, v in olt_entry[ATTRIBUTES_KEY].items()
                                if AA.SetByCreate in
                                next((attr.access for attr in me_entry.attributes
                                      if attr.field.name == k), set())}

                    frame = OmciFrame(transaction_id=None,
                                      message_type=OmciCreate.message_id,
                                      omci_message=OmciCreate(entity_class=cid,
                                                              entity_id=eid,
                                                              data=sbc_data))

                    self._local_deferred = yield self._device.omci_cc.send(frame)
                    self.check_status_and_state(self._local_deferred, 'olt-create-sbc')
                    successes += 1
                    self._db_updates = 0

                    # Try any writeable attributes now (but not set-by-create)
                    writeable_data = {k: v for k, v in olt_entry[ATTRIBUTES_KEY].items()
                                      if AA.Writable in
                                      next((attr.access for attr in me_entry.attributes
                                            if attr.field.name == k), set())
                                      and AA.SetByCreate not in
                                      next((attr.access for attr in me_entry.attributes
                                            if attr.field.name == k), set())}

                    if len(writeable_data):
                        attributes_mask = me_entry.mask_for(*writeable_data.keys())
                        frame = OmciFrame(transaction_id=None,
                                          message_type=OmciSet.message_id,
                                          omci_message=OmciSet(entity_class=cid,
                                                               entity_id=eid,
                                                               attributes_mask=attributes_mask,
                                                               data=writeable_data))

                        self._local_deferred = yield self._device.omci_cc.send(frame)
                        self.check_status_and_state(self._local_deferred, 'olt-set-writeable')
                        successes += 1

            except Exception as e:
                self.log.exception('olt-only-fix', e=e, cid=cid, eid=eid)
                failures += 1
                self.strobe_watchdog()

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_attributes_only(self, attrs, onu_db, olt_db):
        """
        Fix ME's that were found on both the ONU and OLT, but had differing
        attribute values.  There are several cases to handle here

            o For ME's created on the ONU that have write attributes that
              only exist in the ONU's database, copy these to the OLT/OpenOMCI
              database

            o For all other writeable attributes, the OLT value takes precedence

        :param attrs: (list(int,int,str)) List of tuples where (class_id, inst_id, attribute)
                                          points to the specific ME instance where attributes
                                          are different
        :param onu_db: (dict) ONU Database snapshot at time of audit
        :param olt_db: (dict) OLT Database snapshot at time of audit

        :return: (int, int) successes, failures
        """
        successes = 0
        failures = 0
        me_map = self._device.me_map

        # Collect up attributes on a per CID/EID basis.  This will result in
        # the minimal number of operations to either the database of over
        # the OMCI-CC to the ONU

        attr_map = dict()
        for cid, eid, attribute in attrs:
            if (cid, eid) not in attr_map:
                attr_map[(cid, eid)] = {attribute}
            else:
                attr_map[(cid, eid)].add(attribute)

        for entity_pair, attributes in attr_map.items():
            cid = entity_pair[0]
            eid = entity_pair[1]

            # Skip MEs we cannot encode/decode
            if cid not in me_map:
                self.log.warn('no-me-map-decoder', class_id=cid)
                failures += 1
                continue

            if self.deferred.called:        # Check if task canceled
                break

            # Build up MIB set commands and ONU Set (via OMCI) commands
            # based of the attributes
            me_entry = me_map[cid]
            mib_data_to_save = dict()
            onu_data_to_set = dict()
            olt_attributes = olt_db[cid][eid][ATTRIBUTES_KEY]
            onu_attributes = onu_db[cid][eid][ATTRIBUTES_KEY]

            for attribute in attributes:
                map_access = next((attr.access for attr in me_entry.attributes
                                   if attr.field.name == attribute), set())
                writeable = AA.Writable in map_access or AA.SetByCreate in map_access

                # If only in ONU database snapshot, save it to OLT
                if attribute in onu_attributes and attribute not in olt_attributes:
                    # On onu only
                    mib_data_to_save[attribute] = onu_attributes[attribute]

                elif writeable:
                    # On olt only or in both. Either way OLT wins
                    onu_data_to_set[attribute] = olt_attributes[attribute]

            # Now do the bulk operations For both, check to see if the target
            # is still the same as when the audit was performed. If it is, do
            # the commit.  If not, mark as a failure so an expedited audit will
            # occur and check again.

            if len(mib_data_to_save):
                results = yield self.fix_attributes_only_in_mib(cid, eid, mib_data_to_save)
                successes += results[0]
                failures += results[1]

            if len(onu_data_to_set):
                results = yield self.fix_attributes_only_on_olt(cid, eid, onu_data_to_set, olt_db, me_entry)
                successes += results[0]
                failures += results[1]

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_attributes_only_in_mib(self, cid, eid, mib_data):
        successes = 0
        failures = 0
        try:
            # Get current and verify same as during audit it is missing from our DB
            attributes = mib_data.keys()
            current_entry = self._device.query_mib(cid, eid, attributes)

            if current_entry is not None and len(current_entry):
                clashes = {k: v for k, v in current_entry.items()
                           if k in attributes and v != mib_data[k]}

                if len(clashes):
                    raise ValueError('Existing DB entry for {}/{} attributes clash with audit data. Clash: {}'.
                                     format(cid, eid, clashes))

            self._sync_sm.mib_set(cid, eid, mib_data)
            successes += len(mib_data)
            self.strobe_watchdog()

            # If we do nothing but DB updates for ALOT of MEs, we are
            # blocking other async twisted tasks, be kind and yield
            self._db_updates += 1
            if self._db_updates >= MibReconcileTask.max_sequential_db_updates:
                self._db_updates = 0
                self._local_deferred = yield asleep(MibReconcileTask.db_update_pause)

        except ValueError as e:
            self.log.debug('attribute-changed', e)
            failures += len(mib_data)

        except Exception as e:
            self.log.exception('attribute-only-fix-mib', e=e, cid=cid, eid=eid)
            failures += len(mib_data)

        returnValue((successes, failures))

    @inlineCallbacks
    def fix_attributes_only_on_olt(self, cid, eid, onu_data, olt_db, me_entry):
        successes = 0
        failures = 0

        try:
            # On olt only or in both. Either way OLT wins, first verify that
            # the OLT version is still the same data that we want to
            # update on the ONU. Verify the data for the OLT is the same as
            # at time of audit
            olt_db_entries = {k: v for k, v in olt_db[cid][eid][ATTRIBUTES_KEY].items()
                              if k in onu_data.keys()}
            current_entries = self._sync_sm.query_mib(class_id=cid, instance_id=eid,
                                                      attributes=onu_data.keys())

            still_the_same = all(current_entries.get(k) == v for k, v in olt_db_entries.items())
            if not still_the_same:
                returnValue((0, len(onu_data)))    # Wait for it to stabilize

            # OLT data still matches, do the set operations now
            # while len(onu_data):
            attributes_mask = me_entry.mask_for(*onu_data.keys())
            frame = OmciFrame(transaction_id=None,
                              message_type=OmciSet.message_id,
                              omci_message=OmciSet(entity_class=cid,
                                                   entity_id=eid,
                                                   attributes_mask=attributes_mask,
                                                   data=onu_data))

            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results, 'onu-attribute-update')
            successes += len(onu_data)
            self._db_updates = 0

        except Exception as e:
            self.log.exception('attribute-only-fix-onu', e=e, cid=cid, eid=eid)
            failures += len(onu_data)
            self.strobe_watchdog()

        returnValue((successes, failures))

    @inlineCallbacks
    def _get_current_mds(self):
        self.strobe_watchdog()
        results = yield self._device.omci_cc.send(OntDataFrame().get())

        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        mds = (omci_msg['data']['mib_data_sync'] >> 8) & 0xFF \
            if status == 0 and 'data' in omci_msg and 'mib_data_sync' in omci_msg['data'] else -1
        returnValue(mds)

    @inlineCallbacks
    def update_mib_data_sync(self):
        """
        As the final step of MIB resynchronization, the OLT sets the MIB data sync
        attribute of the ONU data ME to some suitable value of its own choice. It
        then sets its own record of the same attribute to the same value,
        incremented by 1, as explained in clause

        :return: (int, int) success, failure counts
        """
        # Get MDS to set
        self._sync_sm.increment_mib_data_sync()
        new_mds_value = self._sync_sm.mib_data_sync

        # Update it.  The set response will be sent on the OMCI-CC pub/sub bus
        # and the MIB Synchronizer will update this MDS value in the database
        # if successful.
        try:
            # previous_mds = yield self._get_current_mds()

            frame = OntDataFrame(mib_data_sync=new_mds_value).set()

            results = yield self._device.omci_cc.send(frame)
            self.check_status_and_state(results, 'ont-data-mbs-update')

            #########################################
            # Debug.  Verify new MDS value was received. Should be 1 greater
            #         than what was sent
            # new_mds = yield self._get_current_mds()
            # self.log.info('mds-update', previous=previous_mds, new=new_mds_value, now=new_mds)
            # Done
            returnValue((1, 0))

        except TimeoutError as e:
            self.log.debug('ont-data-send-timeout', e=e)
            returnValue((0, 1))

        except Exception as e:
            self.log.exception('ont-data-send', e=e, mds=new_mds_value)
            returnValue((0, 1))

    def check_status_and_state(self, results, operation=''):
        """
        Check the results of an OMCI response.  An exception is thrown
        if the task was cancelled or an error was detected.

        :param results: (OmciFrame) OMCI Response frame
        :param operation: (str) what operation was being performed
        :return: True if successful, False if the entity existed (already created)
        """
        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')
        self.strobe_watchdog()

        self.log.debug(operation, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            return True

        elif status == RC.InstanceExists:
            return False

        msg = '{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'.\
            format(operation, status, error_mask, failed_mask, unsupported_mask)

        raise MibReconcileException(msg)

    def _undecodable(self, cid_eid_list, me_map):
        return [(cid, eid) for cid, eid in cid_eid_list if cid not in me_map]

    def _onu_created(self, cid_eid_list, me_map):
        return [(cid, eid) for cid, eid in cid_eid_list if cid in me_map and
                (OP.Create not in me_map[cid].mandatory_operations and
                 OP.Create not in me_map[cid].optional_operations)]

    def _olt_created(self, cid_eid_list, me_map):
        return [(cid, eid) for cid, eid in cid_eid_list if cid in me_map and
                (OP.Create in me_map[cid].mandatory_operations or
                 OP.Create in me_map[cid].optional_operations)]
