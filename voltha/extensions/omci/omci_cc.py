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
from twisted.internet.defer import TimeoutError, CancelledError, failure, fail, succeed, inlineCallbacks
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *
from voltha.extensions.omci.omci_me import OntGFrame, OntDataFrame, SoftwareImageFrame
from voltha.extensions.omci.me_frame import MEFrame
from voltha.extensions.omci.omci_defs import EntityOperations, ReasonCodes
from common.event_bus import EventBusClient
from enum import IntEnum
from binascii import hexlify


def hexify(buffer):
    """Return a hexadecimal string encoding of input buffer"""
    return ''.join('%02x' % ord(c) for c in buffer)


DEFAULT_OMCI_TIMEOUT = 3                         # Seconds
MAX_OMCI_REQUEST_AGE = 60                        # Seconds
DEFAULT_OMCI_DOWNLOAD_SECTION_SIZE = 31          # Bytes

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
    Get_ALARM_Get_Next = 11,
    Start_Software_Download = 12,
    Download_Section = 13,
    End_Software_Download = 14,
    Activate_Software = 15,
    Commit_Software = 15,


# abbreviations
OP = EntityOperations
RxEvent = OmciCCRxEvents


class OMCI_CC(object):
    """ Handle OMCI Communication Channel specifics for Adtran ONUs"""

    MIN_OMCI_TX_ID_LOW_PRIORITY = 0x0001   # 2 Octets max
    MAX_OMCI_TX_ID_LOW_PRIORITY = 0x7FFF   # 2 Octets max
    MIN_OMCI_TX_ID_HIGH_PRIORITY = 0x8000  # 2 Octets max
    MAX_OMCI_TX_ID_HIGH_PRIORITY = 0xFFFF  # 2 Octets max
    LOW_PRIORITY = 0
    HIGH_PRIORITY = 1

    # Offset into some tuples for pending lists and tx in progress
    PENDING_DEFERRED = 0
    PENDING_FRAME = 1
    PENDING_TIMEOUT = 2
    PENDING_RETRY = 3

    REQUEST_TIMESTAMP = 0
    REQUEST_DEFERRED = 1
    REQUEST_FRAME = 2
    REQUEST_TIMEOUT = 3
    REQUEST_RETRY = 4
    REQUEST_DELAYED_CALL = 5

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

    def __init__(self, adapter_agent, device_id, me_map=None,
                 clock=None):
        self.log = structlog.get_logger(device_id=device_id)
        self._adapter_agent = adapter_agent
        self._device_id = device_id
        self._proxy_address = None
        self._enabled = False
        self._extended_messaging = False
        self._me_map = me_map
        if clock is None:
            self.reactor = reactor
        else:
            self.reactor = clock

        # Support 2 levels of priority since only baseline message set supported
        self._tx_tid = [OMCI_CC.MIN_OMCI_TX_ID_LOW_PRIORITY, OMCI_CC.MIN_OMCI_TX_ID_HIGH_PRIORITY]
        self._tx_request = [None, None]    # Tx in progress (timestamp, defer, frame, timeout, retry, delayedCall)
        self._pending = [list(), list()]   # pending queue (deferred, tx_frame, timeout, retry)
        self._rx_response = [None, None]

        # Statistics
        self._tx_frames = 0
        self._rx_frames = 0
        self._rx_unknown_tid = 0      # Rx OMCI with no Tx TID match
        self._rx_onu_frames = 0       # Autonomously generated ONU frames
        self._rx_onu_discards = 0     # Autonomously generated ONU unknown message types
        self._rx_timeouts = 0
        self._rx_late = 0             # Frame response received after timeout on Tx
        self._rx_unknown_me = 0       # Number of managed entities Rx without a decode definition
        self._tx_errors = 0           # Exceptions during tx request
        self._consecutive_errors = 0  # Rx & Tx errors in a row, a good RX resets this to 0
        self._reply_min = sys.maxint  # Fastest successful tx -> rx
        self._reply_max = 0           # Longest successful tx -> rx
        self._reply_sum = 0.0         # Total seconds for successful tx->rx (float for average)
        self._max_hp_tx_queue = 0     # Maximum size of high priority tx pending queue
        self._max_lp_tx_queue = 0     # Maximum size of low priority tx pending queue

        self.event_bus = EventBusClient()

        # If a list of custom ME Entities classes were provided, insert them into
        # main class_id to entity map.
        # TODO: If this class becomes hidden from the ONU DA, move this to the OMCI State Machine runner

    def __str__(self):
        return "OMCISupport: {}".format(self._device_id)

    def _get_priority_index(self, high_priority):
        """ Centralized logic to help make extended message support easier in the future"""
        return OMCI_CC.HIGH_PRIORITY if high_priority and not self._extended_messaging \
            else OMCI_CC.LOW_PRIORITY

    def _tid_is_high_priority(self, tid):
        """ Centralized logic to help make extended message support easier in the future"""

        return not self._extended_messaging and \
            OMCI_CC.MIN_OMCI_TX_ID_HIGH_PRIORITY <= tid <= OMCI_CC.MAX_OMCI_TX_ID_HIGH_PRIORITY

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
    def rx_late(self):
        return self._rx_late

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

    @property
    def hp_tx_queue_len(self):
        return len(self._pending[OMCI_CC.HIGH_PRIORITY])

    @property
    def lp_tx_queue_len(self):
        return len(self._pending[OMCI_CC.LOW_PRIORITY])

    @property
    def max_hp_tx_queue(self):
        return self._max_hp_tx_queue

    @property
    def max_lp_tx_queue(self):
        return self._max_lp_tx_queue

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
        self.log.debug('rx-onu-frame', frame_type=type(rx_frame))

        msg_type = rx_frame.fields['message_type']
        self._rx_onu_frames += 1

        msg = {TX_REQUEST_KEY: None,
               RX_RESPONSE_KEY: rx_frame}

        if msg_type == EntityOperations.AlarmNotification.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.Alarm_Notification)
            self.reactor.callLater(0,  self.event_bus.publish, topic, msg)

        elif msg_type == EntityOperations.AttributeValueChange.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.AVC_Notification)
            self.reactor.callLater(0,  self.event_bus.publish, topic, msg)

        elif msg_type == EntityOperations.TestResult.value:
            topic = OMCI_CC.event_bus_topic(self._device_id, RxEvent.Test_Result)
            self.reactor.callLater(0,  self.event_bus.publish, topic, msg)

        else:
            self.log.warn('onu-unsupported-autonomous-message', type=msg_type)
            self._rx_onu_discards += 1

    def _update_rx_tx_stats(self, now, ts):
        ts_diff = now - arrow.Arrow.utcfromtimestamp(ts)
        secs = ts_diff.total_seconds()
        self._reply_sum += secs
        if secs < self._reply_min:
            self._reply_min = secs
        if secs > self._reply_max:
            self._reply_max = secs
        return secs

    def receive_message(self, msg):
        """
        Receive and OMCI message from the proxy channel to the OLT.

        Call this from your ONU Adapter on a new OMCI Rx on the proxy channel
        :param msg: (str) OMCI binary message (used as input to Scapy packet decoder)
        """
        if not self.enabled:
            return

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
                rx_frame = msg if isinstance(msg, OmciFrame) else OmciFrame(msg)

            except KeyError as e:
                # Unknown, Unsupported, or vendor-specific ME. Key is the unknown classID
                self.log.debug('frame-decode-key-error', msg=hexlify(msg), e=e)
                rx_frame = self._decode_unknown_me(msg)
                self._rx_unknown_me += 1

            except Exception as e:
                self.log.exception('frame-decode', msg=hexlify(msg), e=e)
                return

            finally:
                omci_entities.entity_id_to_class_map = saved_me_map     # Always restore it.

            rx_tid = rx_frame.fields['transaction_id']
            msg_type = rx_frame.fields['message_type']
            # Filter the Test Result frame and route through receive onu
            # message method.
            if rx_tid == 0 or msg_type == EntityOperations.TestResult.value:
                return self._receive_onu_message(rx_frame)

            # Previously unreachable if this is the very first round-trip Rx or we
            # have been running consecutive errors
            if self._rx_frames == 0 or self._consecutive_errors != 0:
                self.reactor.callLater(0, self._publish_connectivity_event, True)

            self._rx_frames += 1
            self._consecutive_errors = 0

            try:
                high_priority = self._tid_is_high_priority(rx_tid)
                index = self._get_priority_index(high_priority)

                # (timestamp, defer, frame, timeout, retry, delayedCall)
                last_tx_tuple = self._tx_request[index]

                if last_tx_tuple is None or \
                        last_tx_tuple[OMCI_CC.REQUEST_FRAME].fields.get('transaction_id') != rx_tid:
                    # Possible late Rx on a message that timed-out
                    self._rx_unknown_tid += 1
                    self._rx_late += 1
                    return

                ts, d, tx_frame, timeout, retry, dc = last_tx_tuple
                if dc is not None and not dc.cancelled and not dc.called:
                    dc.cancel()

                _secs = self._update_rx_tx_stats(now, ts)

                # Late arrival already serviced by a timeout?
                if d.called:
                    self._rx_late += 1
                    return

            except Exception as e:
                self.log.exception('frame-match', msg=hexlify(msg), e=e)
                if d is not None:
                    return d.errback(failure.Failure(e))
                return

            # Publish Rx event to listeners in a different task
            reactor.callLater(0, self._publish_rx_frame, tx_frame, rx_frame)

            # begin success callback chain (will cancel timeout and queue next Tx message)
            self._rx_response[index] = rx_frame
            d.callback(rx_frame)

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
            OmciAttributeValueChange.message_id: (OmciAttributeValueChange,
                                                   {
                                                       'entity_class': unpack('!H', msg[0:2])[0],
                                                       'entity_id': unpack('!H', msg[2:4])[0],
                                                       'data': {
                                                           UNKNOWN_CLASS_ATTRIBUTE_KEY: hexlify(msg[4:-8])
                                                       },
                                                   }),
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

    def flush(self):
        """Flush/cancel in active or pending Tx requests"""
        requests = []

        for priority in {OMCI_CC.HIGH_PRIORITY, OMCI_CC.LOW_PRIORITY}:
            next_frame, self._tx_request[priority] = self._tx_request[priority], None
            if next_frame is not None:
                requests.append((next_frame[OMCI_CC.REQUEST_DEFERRED], next_frame[OMCI_CC.REQUEST_DELAYED_CALL]))

            requests += [(next_frame[OMCI_CC.PENDING_DEFERRED], None)
                         for next_frame in self._pending[priority]]
            self._pending[priority] = list()

        # Cancel them...
        def cleanup_unhandled_error(_):
            pass    # So the cancel below does not flag an unhandled error

        for d, dc in requests:
            if d is not None and not d.called:
                d.addErrback(cleanup_unhandled_error)
                d.cancel()

            if dc is not None and not dc.called and not dc.cancelled:
                dc.cancel()

    def _get_tx_tid(self, high_priority=False):
        """
        Get the next Transaction ID for a tx.  Note TID=0 is reserved
        for autonomously generated messages from an ONU

        :return: (int) TID
        """
        if self._extended_messaging or not high_priority:
            index = OMCI_CC.LOW_PRIORITY
            min_tid = OMCI_CC.MIN_OMCI_TX_ID_LOW_PRIORITY
            max_tid = OMCI_CC.MAX_OMCI_TX_ID_LOW_PRIORITY
        else:
            index = OMCI_CC.HIGH_PRIORITY
            min_tid = OMCI_CC.MIN_OMCI_TX_ID_HIGH_PRIORITY
            max_tid = OMCI_CC.MAX_OMCI_TX_ID_HIGH_PRIORITY

        tx_tid, self._tx_tid[index] = self._tx_tid[index], self._tx_tid[index] + 1

        if self._tx_tid[index] > max_tid:
            self._tx_tid[index] = min_tid

        return tx_tid

    def _request_failure(self, value, tx_tid, high_priority):
        """
        Handle a transmit failure. Rx Timeouts are handled on the 'dc' deferred and
        will call a different method that may retry if requested.  This routine
        will be called after the final (if any) timeout or other error

        :param value: (Failure) Twisted failure
        :param tx_tid: (int) Associated Tx TID
        """
        index = self._get_priority_index(high_priority)

        if self._tx_request[index] is not None:
            tx_frame = self._tx_request[index][OMCI_CC.REQUEST_FRAME]
            tx_frame_tid = tx_frame.fields['transaction_id']

            if tx_frame_tid == tx_tid:
                timeout = self._tx_request[index][OMCI_CC.REQUEST_TIMEOUT]
                dc = self._tx_request[index][OMCI_CC.REQUEST_DELAYED_CALL]
                self._tx_request[index] = None

                if dc is not None and not dc.called and not dc.cancelled:
                    dc.cancel()

                if isinstance(value, failure.Failure):
                    value.trap(CancelledError)
                    self._rx_timeouts += 1
                    self._consecutive_errors += 1
                    if self._consecutive_errors == 1:
                        reactor.callLater(0, self._publish_connectivity_event, False)

                    self.log.debug('timeout', tx_id=tx_tid, timeout=timeout)
                    value = failure.Failure(TimeoutError(timeout, "Deferred"))
            else:
                # Search pending queue. This may be a cancel coming in from the original
                # task that requested the Tx.  If found, remove
                # from pending queue
                for index, request in enumerate(self._pending[index]):
                    req = request.get(OMCI_CC.PENDING_DEFERRED)
                    if req is not None and req.fields['transaction_id'] == tx_tid:
                        self._pending[index].pop(index)
                        break

        self._send_next_request(high_priority)
        return value

    def _request_success(self, rx_frame, high_priority):
        """
        Handle transmit success (a matching Rx was received)

        :param rx_frame: (OmciFrame) OMCI response frame with matching TID
        :return: (OmciFrame) OMCI response frame with matching TID
        """
        index = self._get_priority_index(high_priority)

        if rx_frame is None:
            rx_frame = self._rx_response[index]

        rx_tid = rx_frame.fields.get('transaction_id')

        if rx_tid is not None:
            if self._tx_request[index] is not None:
                tx_frame = self._tx_request[index][OMCI_CC.REQUEST_FRAME]
                tx_tid = tx_frame.fields['transaction_id']

                if rx_tid == tx_tid:
                    # Remove this request. Next callback in chain initiates next Tx
                    self._tx_request[index] = None
                else:
                    self._rx_late += 1
            else:
                self._rx_late += 1

        self._send_next_request(high_priority)

        # Return rx_frame (to next item in callback list)
        return rx_frame

    def _request_timeout(self, tx_tid, high_priority):
        """
        Tx Request timed out.  Resend immediately if there retries is non-zero.  A
        separate deferred (dc) is used on each actual Tx which is not the deferred
        (d) that is returned to the caller of the 'send()' method.

        If the timeout if the transmitted frame was zero, this is just cleanup of
        that transmit request and not necessarily a transmit timeout

        :param tx_tid: (int) TID of frame
        :param high_priority: (bool) True if high-priority queue
        """
        self.log.debug("_request_timeout", tx_tid=tx_tid)
        index = self._get_priority_index(high_priority)

        if self._tx_request[index] is not None:
            # (0: timestamp, 1: defer, 2: frame, 3: timeout, 4: retry, 5: delayedCall)
            ts, d, frame, timeout, retry, _dc = self._tx_request[index]

            if frame.fields.get('transaction_id', 0) == tx_tid:
                self._tx_request[index] = None

                if timeout > 0:
                    self._rx_timeouts += 1

                    if retry > 0:
                        # Push on front of TX pending queue so that it transmits next with the
                        # original TID
                        self._queue_frame(d, frame, timeout, retry - 1, high_priority, front=True)

                    elif not d.called:
                        d.errback(failure.Failure(TimeoutError(timeout, "Send OMCI TID -{}".format(tx_tid))))
            else:
                self.log.warn('timeout-but-not-the-tx-frame')  # Statement mainly for debugging

        self._send_next_request(high_priority)

    def _queue_frame(self, d, frame, timeout, retry, high_priority, front=False):
        index = self._get_priority_index(high_priority)
        tx_tuple = (d, frame, timeout, retry)        # Pending -> (deferred, tx_frame, timeout, retry)

        if front:
            self._pending[index].insert(0, tuple)
        else:
            self._pending[index].append(tx_tuple)

        # Monitor queue stats
        qlen = len(self._pending[index])

        if high_priority:
            if self._max_hp_tx_queue < qlen:
                self._max_hp_tx_queue = qlen

        elif self._max_lp_tx_queue < qlen:
            self._max_lp_tx_queue = qlen

        self.log.debug("queue-size", index=index, pending_qlen=qlen)

    def send(self, frame, timeout=DEFAULT_OMCI_TIMEOUT, retry=0, high_priority=False):
        """
        Queue the OMCI Frame for a transmit to the ONU via the proxy_channel

        :param frame: (OMCIFrame) Message to send
        :param timeout: (int) Rx Timeout. 0=No response needed
        :param retry: (int) Additional retry attempts on channel failure, default=0
        :param high_priority: (bool) High Priority requests
        :return: (deferred) A deferred that fires when the response frame is received
                            or if an error/timeout occurs
        """
        if not self.enabled or self._proxy_address is None:
            # TODO custom exceptions throughout this code would be helpful
            self._tx_errors += 1
            return fail(result=failure.Failure(Exception('OMCI is not enabled')))

        timeout = float(timeout)
        if timeout > float(MAX_OMCI_REQUEST_AGE):
            self._tx_errors += 1
            msg = 'Maximum timeout is {} seconds'.format(MAX_OMCI_REQUEST_AGE)
            return fail(result=failure.Failure(Exception(msg)))

        if not isinstance(frame, OmciFrame):
            self._tx_errors += 1
            msg = "Invalid frame class '{}'".format(type(frame))
            return fail(result=failure.Failure(Exception(msg)))
        try:
            index = self._get_priority_index(high_priority)
            tx_tid = frame.fields['transaction_id']

            if tx_tid is None:
                tx_tid = self._get_tx_tid(high_priority=high_priority)
                frame.fields['transaction_id'] = tx_tid

            assert tx_tid not in self._pending[index], 'TX TID {} is already exists'.format(tx_tid)
            assert tx_tid > 0, 'Invalid Tx TID: {}'.format(tx_tid)

            # Queue it and request next Tx if tx channel is free
            d = defer.Deferred()

            self._queue_frame(d, frame, timeout, retry, high_priority, front=False)
            self._send_next_request(high_priority)

            if timeout == 0:
                self.log.debug("send-timeout-zero", tx_tid=tx_tid)
                self.reactor.callLater(0, d.callback, 'queued')

            return d

        except Exception as e:
            self._tx_errors += 1
            self._consecutive_errors += 1

            if self._consecutive_errors == 1:
                self.reactor.callLater(0, self._publish_connectivity_event, False)

            self.log.exception('send-omci', e=e)
            return fail(result=failure.Failure(e))

    def _ok_to_send(self, tx_request, high_priority):
        """
        G.988 specifies not to issue a MIB upload or a Software download request
        when a similar action is in progress on the other channel. To keep the
        logic here simple, a new upload/download will not be allowed if either a
        upload/download is going on

        :param tx_request (OmciFrame) Frame to send
        :param high_priority: (bool) for queue selection
        :return: True if okay to dequeue and send frame
        """
        other = self._get_priority_index(not high_priority)

        if self._tx_request[other] is None:
            return True

        this_msg_type = tx_request.fields['message_type'] & 0x1f
        not_allowed = {OP.MibUpload.value,
                       OP.MibUploadNext.value,
                       OP.StartSoftwareDownload.value,
                       OP.DownloadSection.value,
                       OP.EndSoftwareDownload.value}

        if this_msg_type not in not_allowed:
            return True

        other_msg_type = self._tx_request[other][OMCI_CC.REQUEST_FRAME].fields['message_type'] & 0x1f
        return other_msg_type not in not_allowed

    def _send_next_request(self, high_priority):
        """
        Pull next tx request and send it

        :param high_priority: (bool) True if this was a high priority request
        :return: results, so callback chain continues if needed
        """
        index = self._get_priority_index(high_priority)

        if self._tx_request[index] is None:  # TODO or self._tx_request[index][OMCI_CC.REQUEST_DEFERRED].called:
            d = None
            try:
                if len(self._pending[index]) and \
                        not self._ok_to_send(self._pending[index][0][OMCI_CC.PENDING_FRAME],
                                             high_priority):
                    reactor.callLater(0.05, self._send_next_request, high_priority)
                    return

                next_frame = self._pending[index].pop(0)

                d = next_frame[OMCI_CC.PENDING_DEFERRED]
                frame = next_frame[OMCI_CC.PENDING_FRAME]
                timeout = next_frame[OMCI_CC.PENDING_TIMEOUT]
                retry = next_frame[OMCI_CC.PENDING_RETRY]

                tx_tid = frame.fields['transaction_id']

                # NOTE: Since we may need to do an independent ME map on a per-ONU basis
                #       save the current value of the entity_id_to_class_map, then
                #       replace it with our custom one before decode, and then finally
                #       restore it later. Tried other ways but really made the code messy.
                saved_me_map = omci_entities.entity_id_to_class_map
                omci_entities.entity_id_to_class_map = self._me_map

                ts = arrow.utcnow().float_timestamp
                try:
                    self._rx_response[index] = None
                    self._adapter_agent.send_proxied_message(self._proxy_address,
                                                             hexify(str(frame)))
                finally:
                    omci_entities.entity_id_to_class_map = saved_me_map

                self._tx_frames += 1

                # Note: the 'd' deferred in the queued request we just got will
                # already have its success callback queued (callLater -> 0) with a
                # result of "queued".  Here we need time it out internally so
                # we can call cleanup appropriately. G.988 mentions that most ONUs
                # will process an request in < 1 second.
                dc_timeout = timeout if timeout > 0 else 1.0

                # Timeout on internal deferred to support internal retries if requested
                dc = self.reactor.callLater(dc_timeout, self._request_timeout, tx_tid, high_priority)

                # (timestamp, defer, frame, timeout, retry, delayedCall)
                self._tx_request[index] = (ts, d, frame, timeout, retry, dc)

                if timeout > 0:
                    d.addCallbacks(self._request_success, self._request_failure,
                                   callbackArgs=(high_priority,),
                                   errbackArgs=(tx_tid, high_priority))

            except IndexError:
                pass    # Nothing pending in this queue

            except Exception as e:
                self.log.exception('send-proxy-exception', e=e)
                self._tx_request[index] = None
                self.reactor.callLater(0, self._send_next_request, high_priority)

                if d is not None:
                    d.errback(failure.Failure(e))
        else:
            self.log.debug("tx-request-occupied", index=index)

    ###################################################################################
    # MIB Action shortcuts

    def send_mib_reset(self, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        """
        Perform a MIB Reset
        """
        self.log.debug('send-mib-reset')

        frame = OntDataFrame().mib_reset()
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_mib_upload(self, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        self.log.debug('send-mib-upload')

        frame = OntDataFrame().mib_upload()
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_mib_upload_next(self, seq_no, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        self.log.debug('send-mib-upload-next')

        frame = OntDataFrame(sequence_number=seq_no).mib_upload_next()
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_reboot(self, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        """
        Send an ONU Device reboot request (ONU-G ME).

        NOTICE: This method is being deprecated and replaced with a tasks to preform this function
        """
        self.log.debug('send-mib-reboot')

        frame = OntGFrame().reboot()
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_get_all_alarm(self, alarm_retrieval_mode=0, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        self.log.debug('send_get_alarm')

        frame = OntDataFrame().get_all_alarm(alarm_retrieval_mode)
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_get_all_alarm_next(self, seq_no, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        self.log.debug('send_get_alarm_next')

        frame = OntDataFrame().get_all_alarm_next(seq_no)
        return self.send(frame, timeout=timeout, high_priority=high_priority)

    def send_start_software_download(self, image_inst_id, image_size, window_size, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        frame = SoftwareImageFrame(image_inst_id).start_software_download(image_size, window_size-1)
        return self.send(frame, timeout, 3, high_priority=high_priority)
        
    def send_download_section(self, image_inst_id, section_num, data, size=DEFAULT_OMCI_DOWNLOAD_SECTION_SIZE, timeout=0, high_priority=False):
        """
        # timeout=0 indicates no repons needed
        """
        # self.log.debug("send_download_section", instance_id=image_inst_id, section=section_num, timeout=timeout)
        if timeout > 0:
            frame = SoftwareImageFrame(image_inst_id).download_section(True, section_num, data)
        else:
            frame = SoftwareImageFrame(image_inst_id).download_section(False, section_num, data)
        return self.send(frame, timeout, high_priority=high_priority)
        
        # if timeout > 0:
        #     self.reactor.callLater(0, self.sim_receive_download_section_resp, 
        #                            frame.fields["transaction_id"], 
        #                            frame.fields["omci_message"].fields["section_number"])
        # return d

    def send_end_software_download(self, image_inst_id, crc32, image_size, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        frame = SoftwareImageFrame(image_inst_id).end_software_download(crc32, image_size)
        return self.send(frame, timeout, high_priority=high_priority)
        # self.reactor.callLater(0, self.sim_receive_end_software_download_resp, frame.fields["transaction_id"])
        # return d

    def send_active_image(self, image_inst_id, flag=0, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        frame = SoftwareImageFrame(image_inst_id).activate_image(flag)
        return self.send(frame, timeout, high_priority=high_priority)

    def send_commit_image(self, image_inst_id, timeout=DEFAULT_OMCI_TIMEOUT, high_priority=False):
        frame = SoftwareImageFrame(image_inst_id).commit_image()
        return self.send(frame, timeout, high_priority=high_priority)

