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
from twisted.internet.defer import returnValue
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_entities import Ieee8021pMapperServiceProfile
from voltha.extensions.omci.tasks.mib_reconcile_task import MibReconcileTask
from voltha.extensions.omci.database.mib_db_api import ATTRIBUTES_KEY
from twisted.internet.defer import  inlineCallbacks
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import MEFrame

OP = EntityOperations
RC = ReasonCodes
AA = AttributeAccess


class AdtnMibReconcileTask(MibReconcileTask):
    """
    Adtran ONU OpenOMCI MIB Reconcile Task

    For some crazy reason, the ADTRAN ONU does not report the IEEE802.1p Mapper ME
    in the ONU upload even though it does exists.  This results in an 'instance
    exists' error when trying to create it on the ONU
    """
    name = "Adtran MIB Reconcile Task"

    def __init__(self, omci_agent, device_id, diffs):
        super(AdtnMibReconcileTask, self).__init__(omci_agent, device_id, diffs)

        self.name = AdtnMibReconcileTask.name
        self._me_130_okay = False   # Set true once bug is fixed (auto detect)
        self._omci_managed = False  # Set once ONU Data tracking of MIB-Data-Sync supported

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
        # Has IEEE 802.1p reporting Bug fixed?

        if self._me_130_okay or Ieee8021pMapperServiceProfile.class_id in onu_db:
            self._me_130_okay = True
            returnValue(super(AdtnMibReconcileTask, self).fix_olt_only(olt, onu_db, olt_db))

        ############################
        # Base class handles all but ME 130
        local_mes = {Ieee8021pMapperServiceProfile.class_id}
        not_manual = [(cid, eid) for cid, eid in olt if cid not in local_mes]

        results = yield super(AdtnMibReconcileTask, self).fix_olt_only(not_manual,
                                                                       onu_db,
                                                                       olt_db)
        successes = results[0]
        failures = results[1]

        # If IEEE 802.1p mapper needs to be checked, do it manually as the IBONT 602
        # manipulates it during MEF EVC/EVC-Map creation
        for cid in local_mes:
            class_entry = olt_db.get(cid, None)

            if class_entry is not None:
                entries = {k: v for k, v in class_entry.items() if isinstance(k, int)}
                for eid, instance in entries.items():
                    try:
                        self.strobe_watchdog()
                        results = yield self.manual_verification(cid, eid, instance[ATTRIBUTES_KEY])
                        successes += results[0]
                        failures += results[1]

                    except Exception as _e:
                        failures += 1

        returnValue((successes, failures))

    @inlineCallbacks
    def update_mib_data_sync(self):
        """ IBONT version does not support MDS"""
        if self._omci_managed:
            results = yield super(AdtnMibReconcileTask, self).update_mib_data_sync()
            returnValue(results)

        returnValue((1, 0))

    @inlineCallbacks
    def manual_verification(self, cid, eid, attributes):
        # Trim off read-only attributes from ones passed in

        me_map = self._device.me_map
        ro_set = {AA.R}
        ro_attrs = {attr.field.name for attr in me_map[cid].attributes
                    if attr.access == ro_set}
        attributes = {k: v for k, v in attributes.items() if k not in ro_attrs}
        attributes_to_fix = dict()

        try:
            while len(attributes):
                frame = MEFrame(me_map[cid], eid, attributes).get()
                self.strobe_watchdog()
                results = yield self._device.omci_cc.send(frame)
                omci_message = results.fields['omci_message'].fields
                status = omci_message['success_code']

                if status == RC.UnknownEntity.value:
                    self.strobe_watchdog()
                    results = yield self.create_instance(me_map[cid], eid, attributes)
                    returnValue((results[0], results[1]))

                if status != RC.Success.value:
                    self.log.error('manual-check-get-failed', cid=cid, eid=eid,
                                   attributes=attributes, status=status)
                    returnValue((1, 0))

                onu_attr = {k: v for k, v in omci_message['data'].items()}
                attributes_to_fix.update({k: v for k, v in onu_attr.items()
                                         if k in attributes and v != attributes[k]})
                attributes = {k: v for k, v in attributes if k not in onu_attr.keys()}

            if len(attributes_to_fix) > 0:
                try:
                    frame = MEFrame(me_map[cid], eid, attributes_to_fix).set()
                    self.strobe_watchdog()
                    yield self._device.omci_cc.send(frame)
                    returnValue((1, 0))

                except Exception as _e:
                    returnValue((0, 1))

        except Exception as e:
            self.log.exception('manual-check-failed', e=e, cid=cid, eid=eid)
            raise

    @inlineCallbacks
    def create_instance(self, cid, eid, attributes):
        try:
            me_map = self._device.me_map
            frame = MEFrame(me_map[cid], eid, attributes).create()

            self.strobe_watchdog()
            results = yield self._device.omci_cc.send(frame)
            status = results.fields['omci_message'].fields['success_code']
            if status == RC.Success.value or status == RC.InstanceExists.value:
                returnValue((1, 0))

            self.log.error('manual-check-create-failed', cid=cid, eid=eid,
                           attributes=attributes, status=status)
            returnValue((0, 1))

        except Exception as e:
            self.log.exception('manual-check-failed', e=e, cid=cid, eid=eid)
            raise
