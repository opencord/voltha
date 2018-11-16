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
from datetime import datetime
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, TimeoutError, failure
from voltha.extensions.omci.omci_defs import ReasonCodes
from voltha.extensions.omci.omci_frame import OmciFrame, OmciGet


class IntervalDataTaskFailure(Exception):
    pass


class IntervalDataTask(Task):
    """
    OpenOMCI Performance Interval Get Request
    """
    task_priority = Task.DEFAULT_PRIORITY
    name = "Interval Data Task"
    max_payload = 29

    def __init__(self, omci_agent, device_id, class_id, entity_id,
                 max_get_response_payload=max_payload,
                 parent_class_id=None,
                 parent_entity_id=None,
                 upstream=None):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param class_id: (int) ME Class ID
        :param entity_id: (int) ME entity ID
        :param max_get_response_payload: (int) Maximum number of octets in a
                                               single GET response frame
        """
        super(IntervalDataTask, self).__init__(IntervalDataTask.name,
                                               omci_agent,
                                               device_id,
                                               priority=IntervalDataTask.task_priority,
                                               exclusive=False)
        self._local_deferred = None
        self._class_id = class_id
        self._entity_id = entity_id

        self._parent_class_id = parent_class_id
        self._parent_entity_id = parent_entity_id
        self._upstream = upstream

        me_map = self.omci_agent.get_device(self.device_id).me_map
        if self._class_id not in me_map:
            msg = "The requested ME Class () does not exist in the ONU's ME Map".format(self._class_id)
            self.log.warn('unknown-pm-me', msg=msg)
            raise IntervalDataTaskFailure(msg)

        self._entity = me_map[self._class_id]
        self._counter_attributes = self.get_counter_attributes_names_and_size()
        self._max_payload = max_get_response_payload

    def cancel_deferred(self):
        super(IntervalDataTask, self).cancel_deferred()

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
        super(IntervalDataTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_get_interval)

    def stop(self):
        """
        Shutdown the tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(IntervalDataTask, self).stop()

    def get_counter_attributes_names_and_size(self):
        """
        Get all of the counter attributes names and the amount of storage they take

        :return: (dict) Attribute name -> length
        """
        return {name: self._entity.attributes[attr_index].field.sz
                for name, attr_index in self._entity.attribute_name_to_index_map.items()
                if self._entity.attributes[attr_index].is_counter}

    @inlineCallbacks
    def perform_get_interval(self):
        """
        Sync the time
        """
        self.log.info('perform-get-interval', class_id=self._class_id,
                      entity_id=self._entity_id)

        device = self.omci_agent.get_device(self.device_id)
        attr_names = self._counter_attributes.keys()

        final_results = {
            'class_id': self._class_id,
            'entity_id': self._entity_id,
            'me_name': self._entity.__name__,   # Mostly for debugging...
            'interval_utc_time': None,
            'parent_class_id': self._parent_class_id,
            'parent_entity_id': self._parent_entity_id,
            'upstream': self._upstream
            # Counters added here as they are retrieved
        }
        last_end_time = None

        while len(attr_names) > 0:
            # Get as many attributes that will fit. Always include the 1 octet
            # Interval End Time Attribute and 2 octets for the Entity ID

            remaining_payload = self._max_payload - 3
            attributes = list()
            for name in attr_names:
                if self._counter_attributes[name] > remaining_payload:
                    break

                attributes.append(name)
                remaining_payload -= self._counter_attributes[name]

            attr_names = attr_names[len(attributes):]
            attributes.append('interval_end_time')

            frame = OmciFrame(
                transaction_id=None,
                message_type=OmciGet.message_id,
                omci_message=OmciGet(
                    entity_class=self._class_id,
                    entity_id=self._entity_id,
                    attributes_mask=self._entity.mask_for(*attributes)
                )
            )
            self.log.debug('interval-get-request', class_id=self._class_id,
                           entity_id=self._entity_id)
            try:
                self.strobe_watchdog()
                results = yield device.omci_cc.send(frame)

                omci_msg = results.fields['omci_message'].fields
                status = omci_msg['success_code']
                end_time = omci_msg['data'].get('interval_end_time')

                self.log.debug('interval-get-results', class_id=self._class_id,
                               entity_id=self._entity_id, status=status,
                               end_time=end_time)

                if status != ReasonCodes.Success:
                    raise IntervalDataTaskFailure('Unexpected Response Status: {}, Class ID: {}'.
                                                  format(status, self._class_id))
                if last_end_time is None:
                    last_end_time = end_time

                elif end_time != last_end_time:
                    msg = 'Interval End Time Changed during retrieval from {} to {}'\
                        .format(last_end_time, end_time)
                    self.log.info('interval-roll-over', msg=msg, class_id=self._class_id)
                    raise IntervalDataTaskFailure(msg)

                final_results['interval_utc_time'] = datetime.utcnow()
                for attribute in attributes:
                    final_results[attribute] = omci_msg['data'].get(attribute)

            except TimeoutError as e:
                self.log.warn('interval-get-timeout', e=e, class_id=self._class_id,
                              entity_id=self._entity_id, attributes=attributes)
                self.deferred.errback(failure.Failure(e))

            except Exception as e:
                self.log.exception('interval-get-failure', e=e, class_id=self._class_id)
                self.deferred.errback(failure.Failure(e))

        # Successful if here
        self.deferred.callback(final_results)
