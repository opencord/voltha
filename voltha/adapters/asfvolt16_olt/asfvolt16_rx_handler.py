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

"""
Asfvolt16 OLT adapter
"""

import structlog
from twisted.internet.defer import DeferredQueue
import arrow
import binascii
from common.frameio.frameio import hexify
from voltha.protos.events_pb2 import KpiEvent, MetricValuePairs
from voltha.protos.events_pb2 import KpiEventType
from voltha.protos.events_pb2 import AlarmEventType, \
    AlarmEventSeverity, AlarmEventState, AlarmEventCategory

log = structlog.get_logger()

class Asfvolt16RxHandler(object):
    def __init__(self, device_id, adapter, onu_queue):
        self.device_id = device_id
        self.adapter = adapter
        self.onu_discovered_queue = onu_queue
        self.adapter_agent = adapter.adapter_agent
        self.adapter_name = adapter.name
        self.omci_rx_queue = DeferredQueue()

    def remote_echo(self, pkt_type, pon, onu, port, crc_ok, msg_size, msg_data):
        log.info('received-omci-msg',
                 pkt_type=pkt_type,
                 pon_id=pon,
                 onu_id=onu,
                 port_id=port,
                 crc_ok=crc_ok,
                 msg_size=msg_size,
                 msg_data=hexify(msg_data))
        self.omci_rx_queue.put((onu, msg_data))

    def receive_omci_msg(self):
        return self.omci_rx_queue.get()

    def remote_report_stats(self, _object, key, stats_data):
        log.info('received-stats-msg',
                 object=_object,
                 key=key,
                 stats=stats_data)

        prefix = 'voltha.{}.{}'.format(self.adapter_name, self.device_id)

        try:
            ts = arrow.utcnow().timestamp

            prefixes = {
                prefix + '.nni': MetricValuePairs(metrics=stats_data)
                }

            kpi_event = KpiEvent(
                type=KpiEventType.slice,
                ts=ts,
                prefixes=prefixes
            )

            self.adapter_agent.submit_kpis(kpi_event)

        except Exception as e:
            log.exception('failed-to-submit-kpis', e=e)

    def remote_report_event(self, _object, key, event, event_data=None):
        def _convert_serial_data(data):
            b = bytearray()
            b.extend(data)

            return binascii.hexlify(b)

        log.info('received-event-msg',
                 object=_object,
                 key=key,
                 event_str=event,
                 event_data=event_data)

        if _object == 'device':
            # key: {'device_id': <int>}
            # event: 'state-changed'
            #     event_data: {'state_change_successful': <False|True>,
            #                  'new_state': <str> ('active-working'|'inactive')}
            pass
        elif _object == 'nni':
            # key: {'device_id': <int>, 'nni': <int>}
            pass
        elif _object == 'pon_ni':
            # key: {'device_id': <int>, 'pon_ni': <int>}
            # event: 'state-changed'
            #     event_data: {'state_change_successful': <False|True>,
            #                  'new_state': <str> ('active-working'|'inactive')}
            #
            # event: 'onu-discovered'
            #     event_data: {'serial_num_vendor_id': <str>
            #                  'serial_num_vendor_specific': <str>
            #                  'ranging_time': <int>
            #                  'onu_id': <int>
            #                  'us_line_rate': <int> (0=2.5G, 1=10G)
            #                  'ds_pon_id': <int>
            #                  'us_pon_id': <int>
            #                  'tuning_granularity': <int>
            #                  'step_tuning_time': <int>
            #                  'attenuation': <int>
            #                  'power_levelling_caps': <int>}
            if 'onu-discovered' == event and event_data is not None:
                event_data['_device_id'] = key['device_id'] if 'device_id' in key else None
                event_data['_pon_id'] = key['pon_id'] if 'pon_id' in key else None
                event_data['_vendor_id'] = _convert_serial_data(event_data['serial_num_vendor_id']) \
                    if 'serial_num_vendor_id' in event_data else None
                event_data['_vendor_specific'] = _convert_serial_data(event_data['serial_num_vendor_specific']) \
                    if 'serial_num_vendor_specific' in event_data else None

                self.onu_discovered_queue.put(event_data)
                log.info('onu-discovered-event-added-to-queue', event_data=event_data)

        elif _object == 'onu':
            # key: {'device_id': <int>, 'pon_ni': <int>, 'onu_id': <int>}
            # event: 'activation-completed'
            #     event_data: {'activation_successful': <False|True>,
            #                  act_fail_reason': <str>}
            #
            # event: 'deactivation-completed'
            #     event_data: {'deactivation_successful': <False|True>}
            #
            # event: 'ranging-completed'
            #     event_data: {'ranging_successful': <False|True>,
            #                  'ranging_fail_reason': <str>,
            #                  'eqd': <int>,
            #                  'number_of_ploams': <int>,
            #                  'power_level': <int>}
            #
            # event: 'enable-completed'
            #     event_data: {'serial_num-vendor_id': <str>
            #                  'serial_num-vendor_specific: <str>}
            #
            # event: 'disable-completed'
            #     event_data: {'serial_num-vendor_id': <str>
            #                  'serial_num-vendor_specific: <str>}

            # Get child_device from onu_id
            child_device = self.adapter_agent.get_child_device(self.device_id, onu_id=key['onu_id'])
            assert child_device is not None

            # Build the message, the ONU adapter uses the proxy_address
            # to uniquely identify a specific ONU
            msg = {'proxy_address':child_device.proxy_address, 'event':event, 'event_data':event_data}

            # Send the event message to the ONU adapter
            self.adapter_agent.publish_inter_adapter_message(child_device.id, msg)

        elif _object == 'alloc_id':
            # key: {'device_id': <int>, 'pon_ni': <int>, 'onu_id': <int>, 'alloc_id': ,<int>}
            pass
        elif _object == 'gem_port':
            # key: {'device_id': <int>, 'pon_ni': <int>, 'onu_id': <int>, 'gem_port': ,<int>}
            pass
        elif _object == 'trx':
            # key: {'device_id': <int>, 'pon_ni': <int>}
            pass
        elif _object == 'flow_map':
            # key: {'device_id': <int>, 'pon_ni': <int>}
            pass

    def remote_report_alarm(self, _object, key, alarm, status, priority,
                            alarm_data=None):
        log.info('received-alarm-msg',
                 object=_object,
                 key=key,
                 alarm=alarm,
                 status=status,
                 priority=priority,
                 alarm_data=alarm_data)

        id = 'voltha.{}.{}.{}'.format(self.adapter_name, self.device_id, _object)
        description = '{} Alarm - {} - {}'.format(_object.upper(), alarm.upper(),
                                                  'Raised' if status else 'Cleared')

        if priority == 'low':
            severity = AlarmEventSeverity.MINOR
        elif priority == 'medium':
            severity = AlarmEventSeverity.MAJOR
        elif priority == 'high':
            severity = AlarmEventSeverity.CRITICAL
        else:
            severity = AlarmEventSeverity.INDETERMINATE

        try:
            ts = arrow.utcnow().timestamp

            alarm_event = self.adapter_agent.create_alarm(
                id=id,
                resource_id=str(key),
                type=AlarmEventType.EQUIPMENT,
                category=AlarmEventCategory.PON,
                severity=severity,
                state=AlarmEventState.RAISED if status else AlarmEventState.CLEARED,
                description=description,
                context=alarm_data,
                raised_ts = ts)

            self.adapter_agent.submit_alarm(self.device_id, alarm_event)

        except Exception as e:
            log.exception('failed-to-submit-alarm', e=e)

        # take action based on alarm type, only pon_ni and onu objects report alarms
        if object == 'pon_ni':
            # key: {'device_id': <int>, 'pon_ni': <int>}
            # alarm: 'los'
            # status: <False|True>
            pass
        elif object == 'onu':
            # key: {'device_id': <int>, 'pon_ni': <int>, 'onu_id': <int>}
            # alarm: <'los'|'lob'|'lopc_miss'|'los_mic_err'|'dow'|'sf'|'sd'|'suf'|'df'|'tiw'|'looc'|'dg'>
            # status: <False|True>
            pass
