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
from voltha.extensions.omci.omci_defs import ReasonCodes as RC


class AlarmSyncDataFailure(Exception):
    """
    This error is raised by default when the upload fails
    """


class AlarmSyncDataTask(Task):
    """
    OpenOMCI - Synchronize the ONU data
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    name = "Alarm Sync Time Task"

    def __init__(self, omci_agent, device_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        """
        super(AlarmSyncDataTask, self).__init__(AlarmSyncDataTask.name,
                                           omci_agent,
                                           device_id,
                                           priority=AlarmSyncDataTask.task_priority,
                                           exclusive=False)
        self._local_deferred = None

    def cancel_deferred(self):
        super(AlarmSyncDataTask, self).cancel_deferred()

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
        super(AlarmSyncDataTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_alarm_sync_data)

    def stop(self):
        """
        Shutdown the tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AlarmSyncDataTask, self).stop()

    def stop_if_not_running(self):
        if not self.running:
            raise AlarmSyncDataFailure('Update Task was cancelled')

    @inlineCallbacks
    def perform_alarm_sync_data(self):
        """
        Sync the time
        """
        self.log.info('perform-alarm-sync-data')

        try:
            device = self.omci_agent.get_device(self.device_id)

            #########################################
            # ONU Data (ME #2)
            # alarm_retrival_mode=1, time=DEFAULT_OMCI_TIMEOUT
            results = yield device.omci_cc.send_get_all_alarm(alarm_retrival_mode=1)
            self.stop_if_not_running()
            command_sequence_number = results.fields['omci_message'].fields['number_of_commands']

            for seq_no in xrange(command_sequence_number):
                if not device.active or not device.omci_cc.enabled:
                    raise AlarmSyncDataFailure('OMCI and/or ONU is not active')

                for retry in range(0, 3):
                    try:
                        self.log.debug('alarm-data-next-request', seq_no=seq_no,
                                       retry=retry,
                                       command_sequence_number=command_sequence_number)
                        yield device.omci_cc.send_get_all_alarm_next(seq_no)
                        self.stop_if_not_running()
                        self.log.debug('alarm-data-next-success', seq_no=seq_no,
                                       command_sequence_number=command_sequence_number)
                        break

                    except TimeoutError as e:
                        from common.utils.asleep import asleep
                        self.log.warn('alarm-data-timeout', e=e, seq_no=seq_no,
                                      command_sequence_number=command_sequence_number)
                        if retry >= 2:
                            raise AlarmSyncDataFailure('Alarm timeout failure on req {} of {}'.
                                                   format(seq_no + 1, command_sequence_number))
                        yield asleep(0.3)
                        self.stop_if_not_running()

            # Successful if here
            self.log.info('alarm-synchronized')
            self.deferred.callback(command_sequence_number)

        except TimeoutError as e:
            self.log.warn('alarm-sync-time-timeout', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('alarm-sync-time', e=e)
            self.deferred.errback(failure.Failure(e))
