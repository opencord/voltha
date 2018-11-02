#
# Copyright 2017-present Open Networking Foundation
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
OMCI Message support
"""

import sys
import arrow
from twisted.internet import reactor, defer
from twisted.internet.defer import DeferredQueue, TimeoutError, CancelledError, failure, fail
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *
from voltha.extensions.omci.omci_me import OntGFrame, OntDataFrame
from common.event_bus import EventBusClient
from enum import IntEnum
from binascii import hexlify


DEFAULT_OMCI_TIMEOUT = 3            # Seconds
MAX_OMCI_REQUEST_AGE = 60           # Seconds
MAX_OMCI_TX_ID = 0xFFFF             # 2 Octets max

CONNECTED_KEY = 'connected'
TX_REQUEST_KEY = 'tx-request'
RX_RESPONSE_KEY = 'rx-response'
UNKNOWN_CLASS_ATTRIBUTE_KEY = 'voltha-unknown-blob'


class OmciCCRxEvents(IntEnum):
    AVC_Notification = 0,
    MIB_Upload = 1,
    MIB_Upload_Next = 2,
    Create = 3,
    Delete = 4,
    Set = 5,
    Alarm_Notification = 6,
    Test_Result = 7,
    MIB_Reset = 8,
    Connectivity = 9,
    Get_ALARM_Get = 10,
    Get_ALARM_Get_Next = 11


# abbreviations
OP = EntityOperations
RxEvent = OmciCCRxEvents


class OMCI_CC(object):
    """ Handle OMCI Communication Channel specifics for Adtran ONUs"""

    _frame_to_event_type = {
        OmciMibResetResponse.message_id: RxEvent.MIB_Reset,
        OmciMibUploadResponse.message_id: RxEvent.MIB_Upload,
        OmciMibUploadNextResponse.message_id: RxEvent.MIB_Upload_Next,
        OmciCreateResponse.message_id: RxEvent.Create,
        OmciDeleteResponse.message_id: RxEvent.Delete,
        OmciSetResponse.message_id: RxEvent.Set,
        OmciGetAllAlarmsResponse.message_id: RxEvent.Get_ALARM_Get,
        OmciGetAllAlarmsNextResponse.message_id: RxEvent.Get_ALARM_Get_Next
    }

    def __init__(self, adapter_agent, device_id, me_map=None):
        self.log = structlog.get_logger(device_id=device_id)
        self._adapter_agent = adapter_agent
        self._device_id = device_id
        self._proxy_address = None
        self._tx_tid = 1
        self._enabled = False
        self._requests = dict()       # Tx ID -> (timestamp, deferred, tx_frame, timeout)
        self._me_map = me_map

        # Statistics
        self._tx_frames = 0
        self._rx_frames = 0
        self._rx_unknown_tid = 0      # Rx OMCI with no Tx TID match
        self._rx_onu_frames = 0       # Autonomously generated ONU frames
        self._rx_onu_discards = 0     # Autonomously generated ONU unknown message types
        self._rx_timeouts = 0
        self._rx_unknown_me = 0       # Number of managed entities Rx without a decode definition
        self._tx_errors = 0           # Exceptions during tx request
        self._consecutive_errors = 0  # Rx & Tx errors in a row, a good RX resets this to 0
        self._reply_min = sys.maxint  # Fastest successful tx -> rx
        self._reply_max = 0           # Longest successful tx -> rx
        self._reply_sum = 0.0         # Total seconds for successful tx->rx (float for average)

        self.event_bus = EventBusClient()

        # If a list of custom ME Entities classes were provided, insert them into
        # main class_id to entity map.
        # TODO: If this class becomes hidden from the ONU DA, move this to the OMCI State Machine runner

    def __str__(self):
        return "OMCISupport: {}".format(self._device_id)

    @staticmethod
    def event_bus_topic(device_id, event):
        """
        Get the topic name for a given event Frame Type
        :param device_id: (str) ONU Device ID
        :param event: (OmciCCRxEvents) Type of event
        :return: (str) Topic string
        """
        assert event in OmciCCRxEvents, \
            'Event {} is not an OMCI-CC Rx Event'.format(event.name)

        return 'omci-rx:{}:{}'.format(device_id, event.name)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        """
        Enable/disable the OMCI Communications Channel

        :param value: (boolean) True to enable, False to disable
        """
        assert isinstance(value, bool), 'enabled is a boolean'

        if self._enabled != value:
            self._enabled = value
            if self._enabled:
                self._start()
            else:
                self._stop()

    @property
    def tx_frames(self):
        return self._tx_frames

    @property
    def rx_frames(self):
        return self._rx_frames

    @property
    def rx_unknown_tid(self):
        return self._rx_unknown_tid         # Tx TID not found

    @property
    def rx_unknown_me(self):
        return self._rx_unknown_me

    @property
    def rx_onu_frames(self):
        return self._rx_onu_frames

    @property
    def rx_onu_discards(self):
        return self._rx_onu_discards        # Attribute Value change autonomous overflows

    @property
    def rx_timeouts(self):
        return self._rx_timeouts

    @property
    def tx_errors(self):
        return self._tx_errors

    @property
    def consecutive_errors(self):
        return self._consecutive_errors

    @property
    def reply_min(self):
        return int(round(self._reply_min * 1000.0))     # Milliseconds

    @property
    def reply_max(self):
        return int(round(self._reply_max * 1000.0))     # Milliseconds

    @property
    def reply_average(self):
        avg = self._reply_sum / self._rx_frames if self._rx_frames > 0 else 0.0
        return int(round(avg * 1000.0))     # Milliseconds

    def _start(self):
        """
        Start the OMCI Communications Channel
        """
        assert self._enabled, 'Start should only be called if enabled'
        self.flush()

        device = self._adapter_agent.get_device(self._device_id)
        self._proxy_address = device.proxy_address

    def _stop(self):
        """
        Stop the OMCI Communications Channel
        """
        assert not self._enabled, 'Stop should only be called if disabled'
        self.flush()
        self._proxy_address = None

    def _receive_onu_message(self, rx_frame):
        """ Autonomously generated ONU frame Rx handler"""
        self.log.debug('rx-onu-frame', frame_type=type(rx_frame),
                       frame=hexify(str(rx_frame)))

        msg_type = rx_frame.fields['message_type']
        self._rx_onu_frames += 1

        msg = {TX_REQUEST_KEY: None,
               RX_RESPONSE_KEY: rx_frame}

        if msg_type == EntityOperations.AlarmNotification.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.Alarm_Notification)
            reactor.callLater(0,  self.event_bus.publish, topic, msg)

        elif msg_type == EntityOperations.AttributeValueChange.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.AVC_Notification)
            reactor.callLater(0,  self.event_bus.publish, topic, msg)

        elif msg_type == EntityOperations.TestResult.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.Test_Result)
            reactor.callLater(0,  self.event_bus.publish, topic, msg)

        else:
            self.log.warn('onu-unsupported-autonomous-message', type=msg_type)
            self._rx_onu_discards += 1

    def receive_message(self, msg):
        """
        Receive and OMCI message from the proxy channel to the OLT.

        Call this from your ONU Adapter on a new OMCI Rx on the proxy channel
        :param msg: (str) OMCI binary message (used as input to Scapy packet decoder)
        """
        if self.enabled:
            try:
                now = arrow.utcnow()
                d = None

                # NOTE: Since we may need to do an independent ME map on a per-ONU basis
                #       save the current value of the entity_id_to_class_map, then
                #       replace it with our custom one before decode, and then finally
                #       restore it later. Tried other ways but really made the code messy.

                saved_me_map = omci_entities.entity_id_to_class_map
                omci_entities.entity_id_to_class_map = self._me_map

                try:
                    rx_frame = OmciFrame(msg)
                    rx_tid = rx_frame.fields['transaction_id']

                    if rx_tid == 0:
                        return self._receive_onu_message(rx_frame)

                    # Previously unreachable if this is the very first Rx or we
                    # have been running consecutive errors
                    if self._rx_frames == 0 or self._consecutive_errors != 0:
                        reactor.callLater(0, self._publish_connectivity_event, True)

                    self._rx_frames += 1
                    self._consecutive_errors = 0

                except KeyError as e:
                    # Unknown, Unsupported, or vendor-specific ME. Key is the unknown classID
                    self.log.debug('frame-decode-key-error', msg=hexlify(msg), e=e)
                    rx_frame = self._decode_unknown_me(msg)
                    self._rx_unknown_me += 1
                    rx_tid = rx_frame.fields.get('transaction_id')

                except Exception as e:
                    self.log.exception('frame-decode', msg=hexlify(msg), e=e)
                    return

                finally:
                    omci_entities.entity_id_to_class_map = saved_me_map     # Always restore it.

                try:
                    (ts, d, tx_frame, _) = self._requests.pop(rx_tid)

                    ts_diff = now - arrow.Arrow.utcfromtimestamp(ts)
                    secs = ts_diff.total_seconds()
                    self._reply_sum += secs

                    if secs < self._reply_min:
                        self._reply_min = secs

                    if secs > self._reply_max:
                        self._reply_max = secs

                except KeyError as e:
                    # Possible late Rx on a message that timed-out
                    self._rx_unknown_tid += 1
                    self.log.warn('tx-message-missing', rx_id=rx_tid, msg=hexlify(msg))
                    return

                except Exception as e:
                    self.log.exception('frame-match', msg=hexlify(msg), e=e)
                    if d is not None:
                        return d.errback(failure.Failure(e))
                    return

                # Notify sender of completed request
                reactor.callLater(0, d.callback, rx_frame)

                # Publish Rx event to listeners in a different task
                reactor.callLater(0, self._publish_rx_frame, tx_frame, rx_frame)

            except Exception as e:
                self.log.exception('rx-msg', e=e)

    def _decode_unknown_me(self, msg):
        """
        Decode an ME for an unsupported class ID.  This should only occur for a subset
        of message types (Get, Set, MIB Upload Next, ...) and they should only be
        responses as well.

        There are some times below that are commented out. For VOLTHA 2.0, it is
        expected that any get, set, create, delete for unique (often vendor) MEs
        will be coded by the ONU utilizing it and supplied to OpenOMCI as a
        vendor-specific ME during device initialization.

        :param msg: (str) Binary data
        :return: (OmciFrame) resulting frame
        """
        from struct import unpack

        (tid, msg_type, framing) = unpack('!HBB', msg[0:4])

        assert framing == 0xa, 'Only basic OMCI framing supported at this time'
        msg = msg[4:]

        # TODO: Commented out items below are future work (not expected for VOLTHA v2.0)
        (msg_class, kwargs) = {
            # OmciCreateResponse.message_id: (OmciCreateResponse, None),
            # OmciDeleteResponse.message_id: (OmciDeleteResponse, None),
            # OmciSetResponse.message_id: (OmciSetResponse, None),
            # OmciGetResponse.message_id: (OmciGetResponse, None),
            # OmciGetAllAlarmsNextResponse.message_id: (OmciGetAllAlarmsNextResponse, None),
            OmciMibUploadNextResponse.message_id: (OmciMibUploadNextResponse,
                                                   {
                                                       'entity_class': unpack('!H', msg[0:2])[0],
                                                       'entity_id': unpack('!H', msg[2:4])[0],
                                                       'object_entity_class': unpack('!H', msg[4:6])[0],
                                                       'object_entity_id': unpack('!H', msg[6:8])[0],
                                                       'object_attributes_mask': unpack('!H', msg[8:10])[0],
                                                       'object_data': {
                                                           UNKNOWN_CLASS_ATTRIBUTE_KEY: hexlify(msg[10:-4])
                                                       },
                                                   }),
            # OmciAlarmNotification.message_id: (OmciAlarmNotification, None),
            # OmciAttributeValueChange.message_id: (OmciAttributeValueChange,
            #                                       {
            #                                           'entity_class': unpack('!H', msg[0:2])[0],
            #                                           'entity_id': unpack('!H', msg[2:4])[0],
            #                                           'data': {
            #                                               UNKNOWN_CLASS_ATTRIBUTE_KEY: hexlify(msg[4:-8])
            #                                           },
            #                                       }),
            # OmciTestResult.message_id: (OmciTestResult, None),
        }.get(msg_type, None)

        if msg_class is None:
            raise TypeError('Unsupport Message Type for Unknown Decode: {}',
                            msg_type)

        return OmciFrame(transaction_id=tid, message_type=msg_type,
                         omci_message=msg_class(**kwargs))

    def _publish_rx_frame(self, tx_frame, rx_frame):
        """
        Notify listeners of successful response frame
        :param tx_frame: (OmciFrame) Original request frame
        :param rx_frame: (OmciFrame) Response frame
        """
        if self._enabled and isinstance(rx_frame, OmciFrame):
            frame_type = rx_frame.fields['omci_message'].message_id
            event_type = OMCI_CC._frame_to_event_type.get(frame_type)

            if event_type is not None:
                topic = OMCI_CC.event_bus_topic(self._device_id, event_type)
                msg = {TX_REQUEST_KEY: tx_frame,
                       RX_RESPONSE_KEY: rx_frame}

                self.event_bus.publish(topic=topic, msg=msg)

    def _publish_connectivity_event(self, connected):
        """
        Notify listeners of Rx/Tx connectivity over OMCI
        :param connected: (bool) True if connectivity transitioned from unreachable
                                 to reachable
        """
        if self._enabled:
            topic = OMCI_CC.event_bus_topic(self._device_id,
                                            RxEvent.Connectivity)
            msg = {CONNECTED_KEY: connected}
            self.event_bus.publish(topic=topic, msg=msg)

    def flush(self, max_age=0):
        limit = arrow.utcnow().float_timestamp - max_age
        old = [tid for tid, (ts, _, _, _) in self._requests.iteritems()
               if ts <= limit]

        for tid in old:
            (_, d, _, _) = self._requests.pop(tid)
            if d is not None and not d.called:
                d.cancel()

    def _get_tx_tid(self):
        """
        Get the next Transaction ID for a tx.  Note TID=0 is reserved
        for autonomously generated messages from an ONU

        :return: (int) TID
        """
        tx_tid, self._tx_tid = self._tx_tid, self._tx_tid + 1
        if self._tx_tid > MAX_OMCI_TX_ID:
            self._tx_tid = 1

        return tx_tid

    def _request_failure(self, value, tx_tid):
        """
        Handle a transmit failure and/or Rx timeout

        :param value: (Failure) Twisted failure
        :param tx_tid: (int) Associated Tx TID
        """
        if tx_tid in self._requests:
            (_, _, _, timeout) = self._requests.pop(tx_tid)
        else:
            timeout = 0

        if isinstance(value, failure.Failure):
            value.trap(CancelledError)
            self._rx_timeouts += 1
            self._consecutive_errors += 1

            if self._consecutive_errors == 1:
                reactor.callLater(0, self._publish_connectivity_event, False)

            self.log.info('timeout', tx_id=tx_tid, timeout=timeout)
            value = failure.Failure(TimeoutError(timeout, "Deferred"))

        return value

    def _request_success(self, rx_frame):
        """
        Handle transmit success (a matching Rx was received)

        :param rx_frame: (OmciFrame) OMCI response frame with matching TID
        :return: (OmciFrame) OMCI response frame with matching TID
        """
        # At this point, no additional processing is required
        # Continue with Rx Success callbacks.
        return rx_frame

    def send(self, frame, timeout=DEFAULT_OMCI_TIMEOUT):
        """
        Send the OMCI Frame to the ONU via the proxy_channel

        :param frame: (OMCIFrame) Message to send
        :param timeout: (int) Rx Timeout. 0=Forever
        :return: (deferred) A deferred that fires when the response frame is received
                            or if an error/timeout occurs
        """
        self.flush(max_age=MAX_OMCI_REQUEST_AGE)

        assert timeout <= MAX_OMCI_REQUEST_AGE, \
            'Maximum timeout is {} seconds'.format(MAX_OMCI_REQUEST_AGE)
        assert isinstance(frame, OmciFrame), \
            "Invalid frame class '{}'".format(type(frame))

        if not self.enabled or self._proxy_address is None:
            # TODO custom exceptions throughout this code would be helpful
            return fail(result=failure.Failure(Exception('OMCI is not enabled')))

        try:
            tx_tid = frame.fields['transaction_id']
            if tx_tid is None:
                tx_tid = self._get_tx_tid()
                frame.fields['transaction_id'] = tx_tid

            assert tx_tid not in self._requests, 'TX TID {} is already exists'.format(tx_tid)
            assert tx_tid >= 0, 'Invalid Tx TID: {}'.format(tx_tid)

            ts = arrow.utcnow().float_timestamp
            d = defer.Deferred()

            # NOTE: Since we may need to do an independent ME map on a per-ONU basis
            #       save the current value of the entity_id_to_class_map, then
            #       replace it with our custom one before decode, and then finally
            #       restore it later. Tried other ways but really made the code messy.

            saved_me_map = omci_entities.entity_id_to_class_map
            omci_entities.entity_id_to_class_map = self._me_map
            try:
                self._adapter_agent.send_proxied_message(self._proxy_address,
                                                         hexify(str(frame)))
            finally:
                omci_entities.entity_id_to_class_map = saved_me_map

            self._tx_frames += 1
            self._requests[tx_tid] = (ts, d, frame, timeout)

            d.addCallbacks(self._request_success, self._request_failure,
                           errbackArgs=(tx_tid,))

            if timeout > 0:
                d.addTimeout(timeout, reactor)

        except Exception as e:
            self._tx_errors += 1
            self._consecutive_errors += 1

            if self._consecutive_errors == 1:
                reactor.callLater(0, self._publish_connectivity_event, False)

            self.log.exception('send-omci', e=e)
            return fail(result=failure.Failure(e))

        return d

    ###################################################################################
    # MIB Action shortcuts

    def send_mib_reset(self, timeout=DEFAULT_OMCI_TIMEOUT):
        """
        Perform a MIB Reset
        """
        self.log.debug('send-mib-reset')

        frame = OntDataFrame().mib_reset()
        return self.send(frame, timeout)

    def send_mib_upload(self, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send-mib-upload')

        frame = OntDataFrame().mib_upload()
        return self.send(frame, timeout)

    def send_mib_upload_next(self, seq_no, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send-mib-upload-next')

        frame = OntDataFrame(sequence_number=seq_no).mib_upload_next()
        return self.send(frame, timeout)

    def send_reboot(self, timeout=DEFAULT_OMCI_TIMEOUT):
        """
        Send an ONU Device reboot request (ONU-G ME).

        NOTICE: This method is being deprecated and replaced with a tasks to preform this function
        """
        self.log.debug('send-mib-reboot')

        frame = OntGFrame().reboot()
        return self.send(frame, timeout)

    def send_get_all_alarm(self, alarm_retrieval_mode=0, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_get_alarm')

        frame = OntDataFrame().get_all_alarm(alarm_retrieval_mode)
        return self.send(frame, timeout)

    def send_get_all_alarm_next(self, seq_no, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_get_alarm_next')

        frame = OntDataFrame().get_all_alarm_next(seq_no)
        return self.send(frame, timeout)
