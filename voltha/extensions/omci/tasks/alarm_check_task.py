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
from voltha.extensions.omci.omci_defs import ReasonCodes


class AlarmDataTaskFailure(Exception):
    pass


class AlarmDataTask(Task):
    """
    OpenOMCI Alarm Data Get Request
    """
    task_priority = Task.DEFAULT_PRIORITY
    name = "Alarm Data Task"
    max_payload = 29

    def __init__(self, omci_agent, device_id, class_id, entity_id):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME entity ID
        """
        super(AlarmDataTask, self).__init__(AlarmDataTask.name,
                                               omci_agent,
                                               device_id,
                                               priority=AlarmDataTask.task_priority,
                                               exclusive=False)
        self._local_deferred = None
        self._class_id = class_id
        self._entity_id = entity_id
        self._last_number_of_commands = None

    def cancel_deferred(self):
        super(AlarmDataTask, self).cancel_deferred()

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
        super(AlarmDataTask, self).start()
        self._local_deferred = reactor.callLater(0, self.check_alarm_data)

    def stop(self):
        """
        Shutdown the tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AlarmDataTask, self).stop()

    @inlineCallbacks
    def check_alarm_data(self):
        """
        Sync the current alarm sequence number
        """
        self.log.info('perform-get-interval', class_id=self._class_id,
                      entity_id=self._entity_id)

        try:
            device = self.omci_agent.get_device(self.device_id)

            results = yield device.omci_cc.send_get_all_alarm()
            omci_msg = results.fields['omci_message'].fields
            status = omci_msg['success_code']
            alarm_sequence_number = omci_msg['number_of_commands']
            self.log.debug('alarm-data', alarm_sequence_number=alarm_sequence_number)

            if status != ReasonCodes.Success:
                raise AlarmDataTaskFailure('Unexpected Response Status: {}'.
                                           format(status))

            if self._last_number_of_commands is None:
                self._last_number_of_commands = alarm_sequence_number

            elif alarm_sequence_number != self._last_number_of_commands:
                msg = 'The last number of sequence does not match {} to {}' \
                    .format(self._last_number_of_commands, alarm_sequence_number)
                self.log.info('interval-roll-over', msg=msg)
                raise AlarmDataTaskFailure(msg)

            # Successful if here
            self.deferred.callback(alarm_sequence_number)

        except TimeoutError as e:
            self.log.warn('alarm_retrieval_mode', e=e)
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('alarm-get-failure', e=e)
            self.deferred.errback(failure.Failure(e))
