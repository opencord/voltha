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
from task import Task
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure
from voltha.extensions.omci.omci_me import OntGFrame
from voltha.extensions.omci.omci_defs import ReasonCodes as RC
from datetime import datetime


class SyncTimeTask(Task):
    """
    OpenOMCI - Synchronize the ONU time with server
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    name = "Sync Time Task"

    def __init__(self, omci_agent, device_id, use_utc=True):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param use_utc: (bool) Use UTC time if True, otherwise local time
        """
        super(SyncTimeTask, self).__init__(SyncTimeTask.name,
                                           omci_agent,
                                           device_id,
                                           priority=SyncTimeTask.task_priority,
                                           exclusive=False)
        self._local_deferred = None
        self._use_utc = use_utc

    def cancel_deferred(self):
        super(SyncTimeTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start the tasks
        """
        super(SyncTimeTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_sync_time)

    def stop(self):
        """
        Shutdown the tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(SyncTimeTask, self).stop()

    @inlineCallbacks
    def perform_sync_time(self):
        """
        Sync the time
        """
        self.log.debug('perform-sync-time')

        try:
            device = self.omci_agent.get_device(self.device_id)

            #########################################
            # ONT-G (ME #256)
            dt = datetime.utcnow() if self._use_utc else datetime.now()

            results = yield device.omci_cc.send(OntGFrame().synchronize_time(dt))

            omci_msg = results.fields['omci_message'].fields
            status = omci_msg['success_code']
            self.log.debug('sync-time', status=status)

            if status == RC.Success:
                self.log.info('sync-time', success_info=omci_msg['success_info'] & 0x0f)

            assert status == RC.Success, 'Unexpected Response Status: {}'.format(status)

            # Successful if here
            self.deferred.callback(results)

        except TimeoutError as e:
            self.log.warn('sync-time-timeout', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('sync-time', e=e)
            self.deferred.errback(failure.Failure(e))
