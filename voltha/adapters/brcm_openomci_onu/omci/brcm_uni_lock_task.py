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
from voltha.extensions.omci.tasks.task import Task
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, failure, returnValue
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import OntGFrame
from voltha.extensions.omci.omci_me import PptpEthernetUniFrame, VeipUniFrame

RC = ReasonCodes
OP = EntityOperations


class BrcmUniLockException(Exception):
    pass


class BrcmUniLockTask(Task):
    """
    Lock or unlock all discovered UNI/PPTP on the ONU
    """
    task_priority = 200
    name = "Broadcom UNI Lock Task"

    def __init__(self, omci_agent, device_id, lock=True, priority=task_priority):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param lock: (bool) If true administratively lock all the UNI.  If false unlock
        :param priority: (int) OpenOMCI Task priority (0..255) 255 is the highest
        """
        super(BrcmUniLockTask, self).__init__(BrcmUniLockTask.name,
                                                omci_agent,
                                                device_id,
                                                priority=priority,
                                                exclusive=True)
        self._device = omci_agent.get_device(device_id)
        self._lock = lock
        self._results = None
        self._local_deferred = None
        self._config = self._device.configuration

    def cancel_deferred(self):
        super(BrcmUniLockTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start UNI/PPTP Lock/Unlock Task
        """
        super(BrcmUniLockTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_lock)


    @inlineCallbacks
    def perform_lock(self):
        """
        Perform the lock/unlock
        """
        self.log.info('setting-uni-lock-state', lock=self._lock)

        try:
            state = 1 if self._lock else 0

            # lock the whole ont and all the pptp.  some onu dont causing odd behavior.
            msg = OntGFrame(attributes={'administrative_state': state})
            frame = msg.set()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield self._device.omci_cc.send(frame)
            self.strobe_watchdog()

            status = results.fields['omci_message'].fields['success_code']
            self.log.info('response-status', status=status)

            # Success?
            if status in (RC.Success.value, RC.InstanceExists):
                self.log.debug('set-lock-ontg', lock=self._lock)
            else:
                self.log.warn('cannot-set-lock-ontg', lock=self._lock)

            pptp_list = sorted(self._config.pptp_entities) if self._config.pptp_entities else []
            veip_list = sorted(self._config.veip_entities) if self._config.veip_entities else []

            for entity_id in pptp_list:
                pptp_value = self._config.pptp_entities[entity_id]
                msg = PptpEthernetUniFrame(entity_id,
                                           attributes=dict(administrative_state=state))
                self._send_uni_lock_msg(entity_id, pptp_value, msg)

            for entity_id in veip_list:
                veip_value = self._config.veip_entities[entity_id]
                msg = VeipUniFrame(entity_id,
                                           attributes=dict(administrative_state=state))
                self._send_uni_lock_msg(entity_id, veip_value, msg)

            self.deferred.callback(self)

        except Exception as e:
            self.log.exception('setting-uni-lock-state', e=e)
            self.deferred.errback(failure.Failure(e))


    @inlineCallbacks
    def _send_uni_lock_msg(self, entity_id, value, me_message):
        frame = me_message.set()
        self.log.debug('openomci-msg', omci_msg=me_message)
        results = yield self._device.omci_cc.send(frame)
        self.strobe_watchdog()

        status = results.fields['omci_message'].fields['success_code']
        self.log.info('response-status', status=status)

        # Success?
        if status in (RC.Success.value, RC.InstanceExists):
            self.log.debug('set-lock-uni', uni=entity_id, value=value, lock=self._lock)
        else:
            self.log.warn('cannot-set-lock-uni', uni=entity_id, value=value, lock=self._lock)

        returnValue(None)
