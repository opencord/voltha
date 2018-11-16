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
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure
from voltha.extensions.omci.omci_me import OntDataFrame
from voltha.extensions.omci.omci_defs import ReasonCodes as RC


class GetMdsTask(Task):
    """
    OpenOMCI Get MIB Data Sync value task

    On successful completion, this task will call the 'callback' method of the
    deferred returned by the start method and return the value of the MIB
    Data Sync attribute of the ONT Data ME
    """
    task_priority = Task.DEFAULT_PRIORITY
    name = "Get MDS Task"

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(GetMdsTask, self).__init__(GetMdsTask.name,
                                         omci_agent,
                                         device_id,
                                         priority=GetMdsTask.task_priority)
        self._local_deferred = None

    def cancel_deferred(self):
        super(GetMdsTask, self).cancel_deferred()

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
        super(GetMdsTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_get_mds)

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(GetMdsTask, self).stop()

    @inlineCallbacks
    def perform_get_mds(self):
        """
        Get the 'mib_data_sync' attribute of the ONU
        """
        self.log.debug('perform-get-mds')

        try:
            device = self.omci_agent.get_device(self.device_id)

            #########################################
            # Request (MDS supplied value does not matter for a 'get' request)

            self.strobe_watchdog()
            results = yield device.omci_cc.send(OntDataFrame().get())

            omci_msg = results.fields['omci_message'].fields
            status = omci_msg['success_code']

            # Note: Currently the data reported by the Scapy decode is 16-bits since we need
            #       the data field that large in order to support MIB and Alarm Upload Next
            #       commands.  Select only the first 8-bits since that is the size of the MIB
            #       Data Sync attribute
            mds = (omci_msg['data']['mib_data_sync'] >> 8) & 0xFF \
                if 'data' in omci_msg and 'mib_data_sync' in omci_msg['data'] else -1

            self.log.debug('ont-data-mds', status=status, mib_data_sync=mds)

            assert status == RC.Success, 'Unexpected Response Status: {}'.format(status)

            # Successful if here
            self.deferred.callback(mds)

        except TimeoutError as e:
            self.log.warn('get-mds-timeout', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('get-mds', e=e)
            self.deferred.errback(failure.Failure(e))
