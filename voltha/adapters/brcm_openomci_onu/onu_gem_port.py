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

import structlog
from common.frameio.frameio import hexify
from twisted.internet.defer import inlineCallbacks, returnValue
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.omci_defs import *

RC = ReasonCodes

class OnuGemPort(object):
    """
    Broadcom ONU specific implementation
    """
    def __init__(self, gem_id, alloc_id, entity_id,
                 encryption=False,
                 omci_transport=False,
                 multicast=False,
                 tcont_ref=None,
                 traffic_class=None,
                 intf_ref=None,
                 untagged=False,
                 name=None,
                 handler=None):

        self.log = structlog.get_logger(device_id=handler.device_id, gem_id=gem_id)
        self.log.debug('function-entry')

        self.name = name
        self.gem_id = gem_id
        self._alloc_id = alloc_id
        self.tcont_ref = tcont_ref
        self.intf_ref = intf_ref
        self.traffic_class = traffic_class
        self._encryption = encryption
        self._omci_transport = omci_transport
        self.multicast = multicast
        self.untagged = untagged
        self._handler = handler

        self._pon_id = None
        self._onu_id = None
        self._entity_id = entity_id

        # Statistics
        self.rx_packets = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.tx_bytes = 0


    def __str__(self):
        return "GemPort: {}, alloc-id: {}, gem-id: {}".format(self.name,
                                                              self.alloc_id,
                                                              self.gem_id)
    @property
    def pon_id(self):
        self.log.debug('function-entry')
        return self._pon_id

    @pon_id.setter
    def pon_id(self, pon_id):
        self.log.debug('function-entry')
        assert self._pon_id is None or self._pon_id == pon_id, 'PON-ID can only be set once'
        self._pon_id = pon_id

    @property
    def onu_id(self):
        self.log.debug('function-entry')
        return self._onu_id

    @onu_id.setter
    def onu_id(self, onu_id):
        self.log.debug('function-entry', onu_id=onu_id)
        assert self._onu_id is None or self._onu_id == onu_id, 'ONU-ID can only be set once'
        self._onu_id = onu_id

    @property
    def alloc_id(self):
        self.log.debug('function-entry')
        if self._alloc_id is None and self._handler is not None:
            try:
                self._alloc_id = self._handler.pon_port.tconts.get(self.tcont_ref).get('alloc-id')

            except Exception:
                pass

        return self._alloc_id

    @property
    def tcont(self):
        self.log.debug('function-entry')
        tcont_item = self._handler.pon_port.tconts.get(self.tcont_ref)
        return tcont_item

    @property
    def omci_transport(self):
        self.log.debug('function-entry')
        return self._omci_transport

    def to_dict(self):
        self.log.debug('function-entry')
        return {
            'port-id': self.gem_id,
            'alloc-id': self.alloc_id,
            'encryption': self._encryption,
            'omci-transport': self.omci_transport
        }

    @property
    def entity_id(self):
        self.log.debug('function-entry')
        return self._entity_id

    @property
    def encryption(self):
        self.log.debug('function-entry')
        return self._encryption

    @encryption.setter
    def encryption(self, value):
        self.log.debug('function-entry')
        assert isinstance(value, bool), 'encryption is a boolean'

        if self._encryption != value:
            self._encryption = value

    @staticmethod
    def create(handler, gem_port, entity_id):
        log = structlog.get_logger(device_id=handler.device_id, gem_port=gem_port, entity_id=entity_id)
        log.debug('function-entry', gem_port=gem_port, entity_id=entity_id)

        return OnuGemPort(gem_port['gemport-id'],
                          None,
                          entity_id,
                          encryption=gem_port['encryption'],  # aes_indicator,
                          tcont_ref=gem_port['tcont-ref'],
                          name=gem_port['name'],
                          traffic_class=gem_port['traffic-class'],
                          handler=handler,
                          untagged=False)

    @inlineCallbacks
    def add_to_hardware(self, omci,
                        tcont_entity_id,
                        ieee_mapper_service_profile_entity_id,
                        gal_enet_profile_entity_id):
        self.log.debug('function-entry')

        self.log.debug('add-to-hardware', gem_id=self.gem_id,
                       tcont_entity_id=tcont_entity_id,
                       ieee_mapper_service_profile_entity_id=ieee_mapper_service_profile_entity_id,
                       gal_enet_profile_entity_id=gal_enet_profile_entity_id)

        try:
            direction = "downstream" if self.multicast else "bi-directional"
            assert not self.multicast, 'MCAST is not supported yet'

            # TODO: magic numbers here
            msg = GemPortNetworkCtpFrame(
                    self.entity_id,          # same entity id as GEM port
                    port_id=self.gem_id,
                    tcont_id=tcont_entity_id,
                    direction=direction,
                    # TODO: This points to the Priority Queue ME. Class #277.  Use whats discovered in relation to tcont
                    upstream_tm=0x8001
                    #upstream_tm=0x100
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'create-gem-port-network-ctp')

        except Exception as e:
            self.log.exception('gemport-create', e=e)
            raise

        try:
            # TODO: magic numbers here
            msg = GemInterworkingTpFrame(
                self.entity_id,          # same entity id as GEM port
                gem_port_network_ctp_pointer=self.entity_id,
                interworking_option=5,                             # IEEE 802.1
                service_profile_pointer=ieee_mapper_service_profile_entity_id,
                interworking_tp_pointer=0x0,
                pptp_counter=1,
                gal_profile_pointer=gal_enet_profile_entity_id
            )
            frame = msg.create()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'create-gem-interworking-tp')

        except Exception as e:
            self.log.exception('interworking-create', e=e)
            raise

        returnValue(results)

    @inlineCallbacks
    def remove_from_hardware(self, omci):
        self.log.debug('function-entry', omci=omci)
        self.log.debug('remove-from-hardware',  gem_id=self.gem_id)

        try:
            msg = GemInterworkingTpFrame(self.entity_id)
            frame = msg.delete()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'delete-gem-port-network-ctp')
        except Exception as e:
            self.log.exception('interworking-delete', e=e)
            raise

        try:
            msg = GemPortNetworkCtpFrame(self.entity_id)
            frame = msg.delete()
            self.log.debug('openomci-msg', omci_msg=msg)
            results = yield omci.send(frame)
            self.check_status_and_state(results, 'delete-gem-interworking-tp')
        except Exception as e:
            self.log.exception('gemport-delete', e=e)
            raise

        returnValue(results)


    def check_status_and_state(self, results, operation=''):
        self.log.debug('function-entry')
        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug("OMCI Result: %s", operation, omci_msg=omci_msg,
                       status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            return True

        elif status == RC.InstanceExists:
            return False

