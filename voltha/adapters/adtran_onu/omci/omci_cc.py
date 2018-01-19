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
OMCI Message support
"""

import sys
import arrow
from twisted.internet import reactor, defer
from twisted.internet.defer import DeferredQueue, TimeoutError, CancelledError, failure, fail
from voltha.protos import third_party
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *
from omci_entities import add_onu_me_entities

_ = third_party

_MAX_INCOMING_ALARM_MESSAGES = 256
_MAX_INCOMING_AVC_MESSAGES = 256
_MAX_INCOMING_TEST_RESULT_MESSAGES = 64

DEFAULT_OMCI_TIMEOUT = 3            # Seconds
MAX_OMCI_REQUEST_AGE = 60           # Seconds
MAX_OMCI_TX_ID = 0xFFFF             # 2 Octets max

# abbreviations
# ECA = EntityClassAttribute
# AA = AttributeAccess
OP = EntityOperations


class OMCI_CC(object):
    """ Handle OMCI Communication Channel specifics for Adtran ONUs"""

    def __init__(self, adapter_agent, device_id,
                 custom_me_entries=None,
                 alarm_queue_limit=_MAX_INCOMING_ALARM_MESSAGES,
                 avc_queue_limit=_MAX_INCOMING_ALARM_MESSAGES,
                 test_results_queue_limit=_MAX_INCOMING_TEST_RESULT_MESSAGES):

        self.log = structlog.get_logger(device_id=device_id)
        self._adapter_agent = adapter_agent
        self._device_id = device_id
        self._proxy_address = None
        self._tx_tid = 1
        self._enabled = False
        self._requests = dict()       # Tx ID -> (timestamp, deferred, tx_frame, timeout)
        self._alarm_queue = DeferredQueue(size=alarm_queue_limit)
        self._avc_queue = DeferredQueue(size=avc_queue_limit)
        self._test_results_queue = DeferredQueue(size=test_results_queue_limit)

        # Statistics
        self._tx_frames = 0
        self._rx_frames = 0
        self._rx_unknown_tid = 0      # Rx OMCI with no Tx TID match
        self._rx_onu_frames = 0       # Autonomously generated ONU frames
        self._rx_alarm_overflow = 0   # Autonomously generated ONU alarms rx overflow
        self._rx_avc_overflow = 0     # Autonomously generated ONU AVC rx overflow
        self._rx_onu_discards = 0     # Autonomously generated ONU unknown message types
        self._rx_timeouts = 0
        self._tx_errors = 0           # Exceptions during tx request
        self._consecutive_errors = 0  # Rx & Tx errors in a row, a good RX resets this to 0
        self._reply_min = sys.maxint  # Fastest successful tx -> rx
        self._reply_max = 0           # Longest successful tx -> rx
        self._reply_sum = 0.0         # Total seconds for successful tx->rx (float for average)

        # If a list of custom ME Entities classes were provided, insert them into
        # main class_id to entity map.
        # TODO: If this class becomes hidden from the ONU DA, move this to the OMCI State Machine runner

        if custom_me_entries is not None:
            add_onu_me_entities(custom_me_entries)

    def __str__(self):
        return "OMCISupport: {}".format(self._device_id)

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
    def rx_onu_frames(self):
        return self._rx_onu_frames

    @property
    def rx_alarm_overflow(self):
        return self._rx_alarm_overflow      # Alarm ONU autonomous overflows

    @property
    def rx_avc_overflow(self):
        return self._rx_avc_overflow        # Attribute Value change autonomous overflows

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

    @property
    def get_alarm_message(self):
        """
        Attempt to retrieve and remove an ONU Alarm Message from the ONU
        autonomous message queue.

        :return: a Deferred which fires with the next Alarm Frame available in
                 the queue.
        """
        return self._alarm_queue.get()

    @property
    def get_avc_message(self):
        """
        Attempt to retrieve and remove an ONU Attribute Value Change (AVC)
        Message from the ONU autonomous message queue.

        :return: a Deferred which fires with the next AVC Frame available in
                 the queue.
        """
        return self._avc_queue.get()

    @property
    def get_test_results(self):
        """
        Attempt to retrieve and remove an ONU Test Results Message from the
        ONU autonomous message queue.

        :return: a Deferred which fires with the next Test Results Frame is
                 available in the queue.
        """
        return self._test_results_queue.get()

    def _start(self):
        """
        Start the OMCI Communications Channel
        """
        assert self._enabled, 'Start should only be called if enabled'
        #
        # TODO: Perform any other common startup tasks here
        #
        self.flush()

        device = self._adapter_agent.get_device(self._device_id)
        self._proxy_address = device.proxy_address

    def _stop(self):
        """
        Stop the OMCI Communications Channel
        """
        assert not self._enabled, 'Stop should only be called if disabled'
        #
        # TODO: Perform common shutdown tasks here
        #
        self.flush()
        self._proxy_address = None

        # TODO: What is best way to clean up any outstanding futures for these queues
        self._alarm_queue = None
        self._avc_queue = None
        self._test_results_queue = None

    def _receive_onu_message(self, rx_frame):
        """ Autonomously generated ONU frame Rx handler"""
        from twisted.internet.defer import QueueOverflow

        self.log.debug('rx-onu-frame', frame_type=type(rx_frame),
                       frame=hexify(str(rx_frame)))

        # TODO: Signal, via defer if Alarm Overflow or just an event?
        msg_type = rx_frame.fields['message_type']

        self._rx_onu_frames += 1

        if msg_type == EntityOperations.AlarmNotification:
            try:
                self._alarm_queue.put((rx_frame, arrow.utcnow().float_timestamp))

            except QueueOverflow:
                self._rx_alarm_overflow += 1
                self.log.warn('onu-rx-alarm-overflow', cnt=self._rx_alarm_overflow)

        elif msg_type == EntityOperations.AttributeValueChange:
            try:
                self._alarm_queue.put((rx_frame, arrow.utcnow().float_timestamp))

            except QueueOverflow:
                self._rx_avc_overflow += 1
                self.log.warn('onu-rx-avc-overflow', cnt=self._rx_avc_overflow)
        else:
            # TODO: Need to add test results message support

            self.log.warn('onu-unsupported-autonomous-message', type=msg_type)
            self._rx_onu_discards += 1

    def receive_message(self, msg):
        """
        Receive and OMCI message from the proxy channel to the OLT.

        Call this from your ONU Adapter on a new OMCI Rx on the proxy channel
        """
        if self.enabled:
            try:
                now = arrow.utcnow()
                d = None

                try:
                    rx_frame = OmciFrame(msg)
                    rx_tid = rx_frame.fields['transaction_id']

                    if rx_tid == 0:
                        return self._receive_onu_message(rx_frame)

                    self._rx_frames += 1
                    self._consecutive_errors = 0

                except KeyError as e:
                    # TODO: Investigate.  Probably an unknown/unsupported ME
                    # TODO: Can we create a temporary one to hold it so upload does not always fail on new ME's?
                    self.log.exception('frame-decode-key-error', msg=hexlify(msg), e=e)
                    return

                except Exception as e:
                    self.log.exception('frame-decode', msg=hexlify(msg), e=e)
                    return

                try:
                    (ts, d, _, _) = self._requests.pop(rx_tid)

                    ts_diff = now - arrow.Arrow.utcfromtimestamp(ts)
                    secs = ts_diff.total_seconds()
                    self._reply_sum += secs

                    if secs < self._reply_min:
                        self._reply_min = secs

                    if secs > self._reply_max:
                        self._reply_max = secs

                    # TODO: Could also validate response type based on request action

                except KeyError:
                    # Possible late Rx on a message that timed-out
                    self._rx_unknown_tid += 1
                    self.log.warn('tx-message-missing', rx_id=rx_tid, msg=hexlify(msg))
                    return

                except Exception as e:
                    self.log.exception('frame-match', msg=hexlify(msg), e=e)
                    if d is not None:
                        return d.errback(failure.Failure(e))
                    return

                d.callback(rx_frame)

            except Exception as e:
                self.log.exception('rx-msg', e=e)

    def flush(self, max_age=0):
        limit = arrow.utcnow().float_timestamp - max_age
        old = [tid for tid, (ts, _, _, _) in self._requests.iteritems()
               if ts <= limit]

        for tid in old:
            (_, d, _, _) = self._requests.pop(tid)
            if d is not None and not d.called:
                d.cancel()

        self._requests = dict()

        if max_age == 0:
            # Flush autonomous messages (Alarms & AVCs)
            while self._alarm_queue.pending:
                _ = yield self._alarm_queue.get()

            while self._avc_queue.pending:
                _ = yield self._avc_queue.get()

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
            self.log.info('timeout', tx_id=tx_tid, timeout=timeout)
            value = failure.Failure(TimeoutError(timeout, "Deferred"))

        return value

    def _request_success(self, rx_frame):
        """
        Handle transmit success (a matching Rx was received)

        :param rx_frame: (OmciFrame) OMCI response frame with matching TID
        :return: (OmciFrame) OMCI response frame with matching TID
        """
        #
        # TODO: Here we could update the MIB database if we did a set/create/delete
        #       or perhaps a verify if a GET.  Also could increment mib counter
        #
        try:
            if isinstance(rx_frame.omci_message, OmciGetResponse):
                pass    # TODO: Implement MIB check or remove

            elif isinstance(rx_frame.omci_message, OmciSetResponse):
                pass    # TODO: Implement MIB update

            elif isinstance(rx_frame.omci_message, OmciCreateResponse):
                pass    # TODO: Implement MIB update

            elif isinstance(rx_frame.omci_message, OmciDeleteResponse):
                pass    # TODO: Implement MIB update

        except Exception as e:
            self.log.exception('omci-message', e=e)

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

            self._adapter_agent.send_proxied_message(self._proxy_address,
                                                     hexify(str(frame)))
            self._tx_frames += 1
            self._requests[tx_tid] = (ts, d, frame, timeout)

            d.addCallbacks(self._request_success, self._request_failure,
                           errbackArgs=(tx_tid,))

            if timeout > 0:
                d.addTimeout(timeout, reactor)

        except Exception as e:
            self._tx_errors += 1
            self._consecutive_errors += 1
            self.log.exception('send-omci', e=e)
            return fail(result=failure.Failure(e))

        return d

    ###################################################################################
    # TODO: The following three need to be ported to the new OMCI_CC and ME_Frame style
    #       or perhaps made into static methods in the base ME_Frame class.

    def send_mib_reset(self, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send-mib-reset')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id,
                entity_id=entity_id
            )
        )
        return self.send(frame, timeout)

    def send_mib_upload(self, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send-mib-upload')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciMibUpload.message_id,
            omci_message=OmciMibUpload(
                entity_class=OntData.class_id,
                entity_id=0
            )
        )
        return self.send(frame, timeout)

    def send_mib_upload_next(self, seq_no, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send-mib-upload-next')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciMibUploadNext.message_id,
            omci_message=OmciMibUploadNext(
                entity_class=OntData.class_id,
                entity_id=0,
                command_sequence_number=seq_no
            )
        )
        return self.send(frame, timeout)
