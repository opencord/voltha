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
from twisted.internet.defer import DeferredQueue, inlineCallbacks, returnValue, TimeoutError, CancelledError, failure, fail
from voltha.protos import third_party
from common.frameio.frameio import hexify
from voltha.extensions.omci.omci import *

_ = third_party

_MAX_INCOMING_OMCI_MESSAGES = 256
DEFAULT_OMCI_TIMEOUT = 3            # Seconds
MAX_OMCI_REQUEST_AGE = 60           # Seconds
MAX_OMCI_TX_ID = 0xFFFF             # 2 Octets max

# abbreviations
# ECA = EntityClassAttribute
# AA = AttributeAccess
OP = EntityOperations


class OMCISupport(object):
    """ Handle OMCI Specifics for Adtran ONUs"""

    def __init__(self, handler, adapter, device_id):
        self.log = structlog.get_logger(device_id=device_id)
        self._handler = handler
        self._adapter = adapter
        self._device_id = device_id
        self._proxy_address = None
        self._tx_tid = 1
        self._deferred = None         # TODO: Remove later if never used
        self._enabled = False
        self._requests = dict()       # Tx ID -> (timestamp, deferred, tx_frame, timeout)
        self._onu_messages = DeferredQueue(size=_MAX_INCOMING_OMCI_MESSAGES)

        # Statistics
        self._tx_frames = 0
        self._rx_frames = 0
        self._rx_onu_frames = 0       # Autonomously generated ONU frames
        self._rx_timeouts = 0
        self._tx_errors = 0           # Exceptions during tx request
        self._consecutive_errors = 0  # Rx & Tx errors in a row, good rx resets this to 0
        self._reply_min = sys.maxint  # Fastest successful tx -> rx
        self._reply_max = 0           # Longest successful tx -> rx
        self._reply_sum = 0.0         # Total seconds for successful tx->rx (float for average)

    def __str__(self):
        return "OMCISupport: {}".format(self._device_id)

    def _cancel_deferred(self):
        d, self._deferred = self._deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        assert isinstance(value, bool), 'enabled is a boolean'
        if self._enabled != value:
            self._enabled = value
            if self._enabled:
                self.start()
            else:
                self.stop()

    @property
    def tx_frames(self):
        return self._tx_frames

    @property
    def rx_frames(self):
        return self._rx_frames

    @property
    def rx_onu_frames(self):
        return self._rx_onu_frames

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
    def get_onu_autonomous_message(self):
        """
        Attempt to retrieve and remove an object from the ONU autonomous
        message queue.

        :return: a Deferred which fires with the next OmciFrame available in
                 the queue.
        """
        return self._onu_messages.get()

    def start(self):
        assert self._enabled, 'Start should only be called if enabled'
        #
        # TODO: Perform common startup tasks here
        #
        self._cancel_deferred()
        self.flush()

        device = self._adapter.adapter_agent.get_device(self._device_id)
        self._proxy_address = device.proxy_address

    def stop(self):
        assert not self._enabled, 'Stop should only be called if disabled'
        #
        # TODO: Perform common shutdown tasks here
        #
        self._cancel_deferred()
        self.flush()
        self._proxy_address = None
        pass

    def _receive_onu_message(self, rx_frame):
        """ Autonomously generated ONU frame Rx handler"""
        self.log.debug('rx-onu-frame', frame=rx_frame)

        self._rx_onu_frames += 1
        self._onu_messages.put((rx_frame, arrow.utcnow().float_timestamp))

    def receive_message(self, msg):
        """
        Receive and OMCI message from the proxy channel to the OLT
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

                except Exception as e:
                    self.log.exception('frame-decode', e=e)
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
                    self.log.warn('message-missing', rx_id=rx_tid)
                    return

                except Exception as e:
                    self.log.exception('frame-decode', e=e)
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
            # Flush autonomous messages
            while self._onu_messages.pending:
                _ = yield self._onu_messages.get()

    def _get_tx_tid(self):
        """
        Get the next Transaction ID for a tx.  Note 0 is reserved
        for autonomously generated message from an ONU

        :return: (int) TID
        """
        tx_tid, self._tx_tid = self._tx_tid, self._tx_tid + 1
        if self._tx_tid > MAX_OMCI_TX_ID:
            self._tx_tid = 1

        return tx_tid

    def _request_failure(self, value, tx_tid):
        if tx_tid in self._requests:
            (_, _, _, timeout) = self._requests.pop(tx_tid)
        else:
            # tx_msg = None
            timeout = 0

        if isinstance(value, failure.Failure):
            value.trap(CancelledError)
            self._rx_timeouts += 1
            self._consecutive_errors += 1
            self.log.info('timeout', tx_id=tx_tid, timeout=timeout)
            value = failure.Failure(TimeoutError(timeout, "Deferred"))

        return value

    def send(self, frame, timeout=DEFAULT_OMCI_TIMEOUT):
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

            assert tx_tid not in self._requests, 'TX TID is already exists'
            assert tx_tid >= 0, 'Invalid Tx TID: {}'.format(tx_tid)

            ts = arrow.utcnow().float_timestamp
            d = defer.Deferred()

            self._adapter.adapter_agent.send_proxied_message(self._proxy_address,
                                                             hexify(str(frame)))
            self._tx_frames += 1
            self._requests[tx_tid] = (ts, d, frame, timeout)

            d.addErrback(self._request_failure, tx_tid)

            if timeout > 0:
                d.addTimeout(timeout, reactor)

        except Exception as e:
            self._tx_errors += 1
            self._consecutive_errors += 1
            self.log.exception('send-omci', e=e)
            return fail(result=failure.Failure(e))

        return d

    def send_get_OntG(self, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_get_OntG')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=OntG.class_id,
                entity_id=entity_id,
                attributes_mask=OntG.mask_for(attribute)
            )
        )
        return self.send(frame, timeout)

    def send_mib_reset(self, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_mib_reset')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id,
                entity_id=entity_id
            )
        )
        return self.send(frame, timeout)

    def send_set_tcont(self, entity_id, alloc_id, timeout=DEFAULT_OMCI_TIMEOUT):
        data = dict(
            alloc_id=alloc_id
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id=entity_id,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)

    def send_create_gem_port_network_ctp(self, entity_id, port_id,
                                         tcont_id, direction, tm,
                                         timeout=DEFAULT_OMCI_TIMEOUT):

        _directions = {"upstream": 1, "downstream": 2, "bi-directional": 3}

        if _directions.has_key(direction):
            _direction = _directions[direction]
        else:
            self.log.error('invalid-gem-port-direction', direction=direction)
            raise ValueError('Invalid GEM port direction: {_dir}'.format(_dir=direction))

        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemPortNetworkCtp.class_id,
                entity_id=entity_id,
                data=dict(
                    port_id=port_id,
                    tcont_pointer=tcont_id,
                    direction=_direction,
                    traffic_management_pointer_upstream=tm
                )
            )
        )
        return self.send(frame, timeout)

    def send_set_8021p_mapper_service_profile(self, entity_id,
                                              interwork_tp_id,
                                              timeout=DEFAULT_OMCI_TIMEOUT):
        data = dict(
            interwork_tp_pointer_for_p_bit_priority_0=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_1=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_2=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_3=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_4=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_5=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_6=interwork_tp_id,
            interwork_tp_pointer_for_p_bit_priority_7=interwork_tp_id
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                attributes_mask=Ieee8021pMapperServiceProfile.mask_for(
                    *data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)

    def send_create_8021p_mapper_service_profile(self, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_1=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_2=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_3=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_4=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_5=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_6=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_7=OmciNullPointer
                )
            )
        )
        return self.send(frame, timeout)

    def send_create_mac_bridge_service_profile(self, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgeServiceProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    spanning_tree_ind=False,
                    learning_ind=True,
                    priority=0x8000,
                    max_age=20 * 256,
                    hello_time=2 * 256,
                    forward_delay=15 * 256,
                    unknown_mac_address_discard=True
                )
            )
        )
        return self.send(frame, timeout)

    def send_create_gal_ethernet_profile(self, entity_id, max_gem_payload_size,
                                         timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GalEthernetProfile.class_id,
                entity_id=entity_id,
                data=dict(
                    max_gem_payload_size=max_gem_payload_size
                )
            )
        )
        return self.send(frame, timeout)

    def send_create_gem_inteworking_tp(self, entity_id, gem_port_net_ctp_id,
                                       service_profile_id, timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemInterworkingTp.class_id,
                entity_id=entity_id,
                data=dict(
                    gem_port_network_ctp_pointer=gem_port_net_ctp_id,
                    interworking_option=5,
                    service_profile_pointer=service_profile_id,
                    interworking_tp_pointer=0x0,
                    gal_profile_pointer=0x1
                )
            )
        )
        return self.send(frame, timeout)

    def send_create_mac_bridge_port_configuration_data(self, entity_id, bridge_id,
                                                       port_id, tp_type, tp_id,
                                                       timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    bridge_id_pointer=bridge_id,
                    port_num=port_id,
                    tp_type=tp_type,
                    tp_pointer=tp_id
                )
            )
        )
        return self.send(frame, timeout)

    def send_create_vlan_tagging_filter_data(self, entity_id, vlan_id,
                                             timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=entity_id,
                data=dict(
                    vlan_filter_0=vlan_id,
                    forward_operation=0x10,
                    number_of_entries=1
                )
            )
        )
        return self.send(frame, timeout)

    # def send_get_device_info(self, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
    #     # TODO: Can this be combined with send_get_circuit_pack above?
    #     frame = OmciFrame(
    #         transaction_id=self._get_tx_tid(),
    #         message_type=OmciGet.message_id,
    #         omci_message=OmciGet(
    #             entity_class=CircuitPack.class_id,
    #             entity_id=entity_id,
    #             attributes_mask=CircuitPack.mask_for(attribute)
    #         )
    #     )
    #     return self.send(frame, timeout)

    def send_set_adminState(self, entity_id, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_set_AdminState')
        data = dict(
            administrative_state=0
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=PptpEthernetUni.class_id,
                entity_id=entity_id,
                attributes_mask=PptpEthernetUni.mask_for(*data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)

    def send_get_SoftwareImage(self, attribute, entity_id=0, timeout=DEFAULT_OMCI_TIMEOUT):
        self.log.debug('send_get_SoftwareImage')
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=SoftwareImage.class_id,
                entity_id=entity_id,
                attributes_mask=SoftwareImage.mask_for(attribute)
            )
        )
        return self.send(frame, timeout)

    def send_create_extended_vlan_tagging_operation_configuration_data(self,
                                                                       entity_id,
                                                                       assoc_type,
                                                                       assoc_me,
                                                                       timeout=DEFAULT_OMCI_TIMEOUT):
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=
                ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                data=dict(
                    association_type=assoc_type,
                    associated_me_pointer=assoc_me
                )
            )
        )
        return self.send(frame, timeout)

    def send_set_extended_vlan_tagging_operation_tpid_configuration_data(self,
                                                                         entity_id,
                                                                         input_tpid,
                                                                         output_tpid,
                                                                         timeout=DEFAULT_OMCI_TIMEOUT):
        data = dict(
            input_tpid=input_tpid,
            output_tpid=output_tpid,
            downstream_mode=0,  # inverse of upstream
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                ExtendedVlanTaggingOperationConfigurationData.mask_for(
                    *data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_untagged(self,
                                                                                  entity_id,
                                                                                  filter_inner_vid,
                                                                                  treatment_inner_vid,
                                                                                  timeout=DEFAULT_OMCI_TIMEOUT):
        data = dict(
            received_frame_vlan_tagging_operation_table=
            VlanTaggingOperation(
                filter_outer_priority=15,
                filter_outer_vid=4096,
                filter_outer_tpid_de=0,

                filter_inner_priority=15,
                filter_inner_vid=filter_inner_vid,
                filter_inner_tpid_de=0,
                filter_ether_type=0,

                treatment_tags_to_remove=0,
                treatment_outer_priority=15,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=0,

                treatment_inner_priority=0,
                treatment_inner_vid=treatment_inner_vid,
                treatment_inner_tpid_de=4
            )
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                ExtendedVlanTaggingOperationConfigurationData.mask_for(
                    *data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)

    def send_set_extended_vlan_tagging_operation_vlan_configuration_data_single_tag(self,
                                                                                    entity_id,
                                                                                    filter_inner_priority,
                                                                                    filter_inner_vid,
                                                                                    filter_inner_tpid_de,
                                                                                    treatment_tags_to_remove,
                                                                                    treatment_inner_priority,
                                                                                    treatment_inner_vid,
                                                                                    timeout=DEFAULT_OMCI_TIMEOUT):
        data = dict(
            received_frame_vlan_tagging_operation_table=
            VlanTaggingOperation(
                filter_outer_priority=15,
                filter_outer_vid=4096,
                filter_outer_tpid_de=0,
                filter_inner_priority=filter_inner_priority,
                filter_inner_vid=filter_inner_vid,
                filter_inner_tpid_de=filter_inner_tpid_de,
                filter_ether_type=0,
                treatment_tags_to_remove=treatment_tags_to_remove,
                treatment_outer_priority=15,
                treatment_outer_vid=0,
                treatment_outer_tpid_de=0,
                treatment_inner_priority=treatment_inner_priority,
                treatment_inner_vid=treatment_inner_vid,
                treatment_inner_tpid_de=4
            )
        )
        frame = OmciFrame(
            transaction_id=self._get_tx_tid(),
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=
                ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=entity_id,
                attributes_mask=
                ExtendedVlanTaggingOperationConfigurationData.mask_for(
                    *data.keys()),
                data=data
            )
        )
        return self.send(frame, timeout)
