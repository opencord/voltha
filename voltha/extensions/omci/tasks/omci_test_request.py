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

import arrow
from task import Task
from twisted.internet.task import LoopingCall
from twisted.internet.defer import failure, inlineCallbacks, TimeoutError
from voltha.extensions.omci.omci_defs import ReasonCodes, EntityOperations
from voltha.extensions.omci.omci_me import MEFrame
from common.event_bus import EventBusClient
from voltha.protos.events_pb2 import KpiEvent2, KpiEventType, KpiEvent
from voltha.protos.events_pb2 import MetricInformation, MetricMetaData

RC = ReasonCodes
OP = EntityOperations


class TestFailure(Exception):
    pass


class OmciTestRequest(Task):
    """
    OpenOMCI Test an OMCI ME Instance Attributes

    Upon completion, the Task deferred callback is invoked with a reference of
    this Task object.

    """
    task_priority = 128
    name = "ONU OMCI Test Task"
    MAX_TABLE_SIZE = 16 * 1024  # Keep get-next logic reasonable
    OPTICAL_GROUP_NAME = 'PON_Optical'
    DEFAULT_COLLECTION_FREQUENCY = 600 * 10 # 10 minutes
    DEFAULT_FREQUENCY_KEY = 'default-collection-frequency'

    def __init__(self, omci_agent, device_id, entity_class, serial_number,
                 logical_device_id,
                 exclusive=True, allow_failure=False, **kwargs):
        """
        Class initialization

        :param omci_agent: (OmciAdapterAgent) OMCI Adapter agent
        :param device_id: (str) ONU Device ID
        :param entity_class: (EntityClass) ME Class to retrieve
        :param entity_id: (int) ME Class instance ID to retrieve
        :param attributes: (list or set) Name of attributes to retrieve
        :param exclusive: (bool) True if this GET request Task exclusively own the
                                 OMCI-CC while running. Default: True
        :param allow_failure: (bool) If true, attempt to get all valid attributes
                                     if the original request receives an error
                                     code of 9 (Attributes failed or unknown).
        """
        super(OmciTestRequest, self).__init__(OmciTestRequest.name,
                                              omci_agent,
                                              device_id,
                                              priority=OmciTestRequest.task_priority,
                                              exclusive=exclusive)
        self._device = omci_agent.get_device(device_id)
        self._entity_class = entity_class
        self._allow_failure = allow_failure
        self._failed_or_unknown_attributes = set()
        self._results = None
        self._local_deferred = None
        self.device_id = device_id
        self.event_bus = EventBusClient()
        self.lc = None
        self.default_freq = self.default_freq = \
            kwargs.get(OmciTestRequest.DEFAULT_FREQUENCY_KEY,
                       OmciTestRequest.DEFAULT_COLLECTION_FREQUENCY)
        self.serial_number = serial_number
        self.logical_device_id =  logical_device_id
        topic = 'omci-rx:{}:{}'.format(self.device_id, 'Test_Result')
        self.msg = self.event_bus.subscribe(topic, self.process_messages)

    def cancel_deferred(self):
        """

        :return: None
        """
        super(OmciTestRequest, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def me_class(self):
        """The OMCI Managed Entity Class associated with this request"""
        return self._entity_class

    @property
    def entity_id(self):
        """The ME Entity ID associated with this request"""
        return self._entity_id

    @property
    def success_code(self):
        """
        Return the OMCI success/reason code for the Get Response.
        """
        if self._results is None:
            return None
        return self._results.fields['omci_message'].fields['success']

    def start_collector(self, callback=None):
        """
                Start the collection loop for an adapter if the frequency > 0

                :param callback: (callable) Function to call to collect PM data
        """
        self.log.info("starting-pm-collection", device_name=self.name)
        if callback is None:
            callback = self.perform_test_omci

        if self.lc is None:
            self.lc = LoopingCall(callback)

        if self.default_freq > 0:
            self.lc.start(interval=self.default_freq / 10)

    def submit_kpis(self, kpi_event):
        """

        :param kpi_event: List of dict.actual event information.
        :return: None
        """
        try:
            assert isinstance(kpi_event, (KpiEvent, KpiEvent2))
            self.event_bus.publish('kpis', kpi_event)
        except Exception as e:
            self.log.exception('failed-kpi-submission',
                               type=type(kpi_event))

    def publish_metrics(self, data, event_name, onu_device_id):
        """

        :param data:  actual test result dict
        :param event_name: Test_result
        :param onu_device_id:  Onu device id
        :return: None
        """
        metric_data = MetricInformation(
            metadata=MetricMetaData(title=OmciTestRequest.OPTICAL_GROUP_NAME,
                                    ts=arrow.utcnow().float_timestamp,
                                    logical_device_id=self.logical_device_id,
                                    serial_no=self.serial_number,
                                    device_id=onu_device_id,
                                    context={
                                        'events': event_name
                                    }),
            metrics=data)
        self.log.info('Publish-Test-Result')
        kpi_event = KpiEvent2(
            type=KpiEventType.slice,
            ts=arrow.utcnow().float_timestamp,
            slice_data=[metric_data])

        self.submit_kpis(kpi_event)

    def process_messages(self, topic, msg):
        """

        :param topic: topic name of onu.
        :param msg: actual test result dict
        :return: None
        """
        result_frame = {}
        event_name = topic.split(':')[-1]
        onu_device_id = topic.split(':')[-2]
        frame = msg['rx-response']
        for key, value in (frame.fields['omci_message'].fields).iteritems():
            result_frame[key] = long(value)
        self.publish_metrics(result_frame, event_name, onu_device_id)

    @inlineCallbacks
    def perform_test_omci(self):
        """
        Perform the initial test request
        """
        ani_g_entities = self._device.configuration.ani_g_entities
        ani_g_entities_ids = ani_g_entities.keys() if ani_g_entities \
                                                      is not None else None
        self._entity_id = ani_g_entities_ids[0]

        self.log.info('perform-test', entity_class=self._entity_class,
                      entity_id=self._entity_id)
        try:
            frame = MEFrame(self._entity_class, self._entity_id, []).test()
            result = yield self._device.omci_cc.send(frame)
            if not result.fields['omci_message'].fields['success_code']:
                self.log.info('Self-Test Submitted Successfully',code=result.fields[
                    'omci_message'].fields['success_code'])
            else:
                raise TestFailure('Test Failure: {}'.format(
                    result.fields['omci_message'].fields['success_code']))
        except TimeoutError as e:
            self.deferred.errback(failure.Failure(e))

        except Exception as e:
            self.log.exception('perform-test', e=e, class_id=self._entity_class,
                               entity_id=self._entity_id)
            self.deferred.errback(failure.Failure(e))
