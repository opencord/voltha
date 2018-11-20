#
# Copyright 2017-present Adtran, Inc.
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

import random
import arrow

import structlog
import xmltodict
from port import AdtnPort
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed, fail
from twisted.python.failure import Failure
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port


class NniPort(AdtnPort):
    """
    Northbound network port, often Ethernet-based
    """
    def __init__(self, parent, **kwargs):
        super(NniPort, self).__init__(parent, **kwargs)

        # TODO: Weed out those properties supported by common 'Port' object

        self.log = structlog.get_logger(port_no=kwargs.get('port_no'))
        self.log.info('creating')

        # ONOS/SEBA wants 'nni-<port>' for port names, OLT NETCONF wants their
        # name (something like  hundred-gigabit-ethernet 0/1) which is reported
        # when we enumerated the ports
        self._physical_port_name = kwargs.get('name', 'nni-{}'.format(self._port_no))
        self._logical_port_name = 'nni-{}'.format(self._port_no)
        self._logical_port = None

        self.sync_tick = 10.0

        self._stats_tick = 5.0
        self._stats_deferred = None

        # Local cache of NNI configuration
        self._ianatype = '<type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">ianaift:ethernetCsmacd</type>'

        # And optional parameters
        # TODO: Currently cannot update admin/oper status, so create this enabled and active
        # self._admin_state = kwargs.pop('admin_state', AdminState.UNKNOWN)
        # self._oper_status = kwargs.pop('oper_status', OperStatus.UNKNOWN)
        self._enabled = True
        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._label = self._physical_port_name
        self._mac_address = kwargs.pop('mac_address', '00:00:00:00:00:00')
        # TODO: Get with JOT and find out how to pull out MAC Address via NETCONF
        # TODO: May need to refine capabilities into current, advertised, and peer

        self._ofp_capabilities = kwargs.pop('ofp_capabilities', OFPPF_100GB_FD | OFPPF_FIBER)
        self._ofp_state = kwargs.pop('ofp_state', OFPPS_LIVE)
        self._current_speed = kwargs.pop('current_speed', OFPPF_100GB_FD)
        self._max_speed = kwargs.pop('max_speed', OFPPF_100GB_FD)
        self._device_port_no = kwargs.pop('device_port_no', self._port_no)

        # Statistics
        self.rx_dropped = 0
        self.rx_error_packets = 0
        self.rx_ucast_packets = 0
        self.rx_bcast_packets = 0
        self.rx_mcast_packets = 0
        self.tx_dropped = 0
        self.rx_ucast_packets = 0
        self.tx_bcast_packets = 0
        self.tx_mcast_packets = 0

    def __str__(self):
        return "NniPort-{}: Admin: {}, Oper: {}, parent: {}".format(self._port_no,
                                                                    self._admin_state,
                                                                    self._oper_status,
                                                                    self._parent)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        self.log.debug('get-port-status-update', port=self._port_no,
                       label=self._label)
        if self._port is None:
            self._port = Port(port_no=self._port_no,
                              label=self._label,
                              type=Port.ETHERNET_NNI,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status)

        if self._port.admin_state != self._admin_state or\
           self._port.oper_status != self._oper_status:

            self.log.debug('get-port-status-update', admin_state=self._admin_state,
                           oper_status=self._oper_status)
            self._port.admin_state = self._admin_state
            self._port.oper_status = self._oper_status

        return self._port

    @property
    def iana_type(self):
        return self._ianatype

    def cancel_deferred(self):
        super(NniPort, self).cancel_deferred()

        d, self._stats_deferred = self._stats_deferred, None
        try:
            if d is not None and d.called:
                d.cancel()
        except:
            pass

    def _update_adapter_agent(self):
        # adapter_agent add_port also does an update of port status
        self.log.debug('update-adapter-agent', admin_state=self._admin_state,
                       oper_status=self._oper_status)
        self.adapter_agent.add_port(self.olt.device_id, self.get_port())

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port
        :return: VOLTHA logical port or None if not supported
        """
        if self._logical_port is None:
            openflow_port = ofp_port(port_no=self._port_no,
                                     hw_addr=mac_str_to_tuple(self._mac_address),
                                     name=self._logical_port_name,
                                     config=0,
                                     state=self._ofp_state,
                                     curr=self._ofp_capabilities,
                                     advertised=self._ofp_capabilities,
                                     peer=self._ofp_capabilities,
                                     curr_speed=self._current_speed,
                                     max_speed=self._max_speed)

            self._logical_port = LogicalPort(id=self._logical_port_name,
                                             ofp_port=openflow_port,
                                             device_id=self._parent.device_id,
                                             device_port_no=self._device_port_no,
                                             root_port=True)
        return self._logical_port

    @inlineCallbacks
    def finish_startup(self):

        if self.state != AdtnPort.State.INITIAL:
            returnValue('Done')

        self.log.debug('final-startup')
        # TODO: Start status polling of NNI interfaces
        self.deferred = None  # = reactor.callLater(3, self.do_stuff)

        # Begin statistics sync
        self._stats_deferred = reactor.callLater(self._stats_tick * 2, self._update_statistics)

        try:
            yield self.set_config('enabled', True)

            super(NniPort, self).finish_startup()

        except Exception as e:
            self.log.exception('nni-start', e=e)
            self._oper_status = OperStatus.UNKNOWN
            self._update_adapter_agent()

        returnValue('Enabled')

    def finish_stop(self):

        # NOTE: Leave all NNI ports active (may have inband management)
        # TODO: Revisit leaving NNI Ports active on disable

        return self.set_config('enabled', False)

    @inlineCallbacks
    def reset(self):
        """
        Set the NNI Port to a known good state on initial port startup.  Actual
        NNI 'Start' is done elsewhere
        """
        # if self.state != AdtnPort.State.INITIAL:
        #     self.log.error('reset-ignored', state=self.state)
        #     returnValue('Ignored')

        self.log.info('resetting', label=self._label)

        # Always enable our NNI ports

        try:
            results = yield self.set_config('enabled', True)
            self._admin_state = AdminState.ENABLED
            self._enabled = True
            returnValue(results)

        except Exception as e:
            self.log.exception('reset', e=e)
            self._admin_state = AdminState.UNKNOWN
            raise

    @inlineCallbacks
    def set_config(self, leaf, value):
        if isinstance(value, bool):
            value = 'true' if value else 'false'

        config = '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' + \
                 ' <interface>' + \
                 '  <name>{}</name>'.format(self._physical_port_name) + \
                 '  {}'.format(self._ianatype) + \
                 '  <{}>{}</{}>'.format(leaf, value, leaf) + \
                 ' </interface>' + \
                 '</interfaces>'
        try:
            results = yield self._parent.netconf_client.edit_config(config)
            returnValue(results)

        except Exception as e:
            self.log.exception('set', leaf=leaf, value=value, e=e)
            raise

    def get_nni_config(self):
        config = '<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' + \
                 ' <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' + \
                 '  <interface>' + \
                 '   <name>{}</name>'.format(self._physical_port_name) + \
                 '   <enabled/>' + \
                 '  </interface>' + \
                 ' </interfaces>' + \
                 '</filter>'
        return self._parent.netconf_client.get(config)

    def get_nni_statistics(self):
        state = '<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' + \
                 ' <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">' + \
                 '  <interface>' + \
                 '   <name>{}</name>'.format(self._physical_port_name) + \
                 '   <admin-status/>' + \
                 '   <oper-status/>' + \
                 '   <statistics/>' + \
                 '  </interface>' + \
                 ' </interfaces>' + \
                 '</filter>'
        return self._parent.netconf_client.get(state)

    def sync_hardware(self):
        if self.state == AdtnPort.State.RUNNING or self.state == AdtnPort.State.STOPPED:
            def read_config(results):
                #self.log.debug('read-config', results=results)
                try:
                    result_dict = xmltodict.parse(results.data_xml)
                    interfaces = result_dict['data']['interfaces']
                    if 'if:interface' in interfaces:
                        entries = interfaces['if:interface']
                    else:
                        entries = interfaces['interface']

                    enabled = entries.get('enabled',
                                          str(not self.enabled).lower()) == 'true'

                    if self.enabled == enabled:
                        return succeed('in-sync')

                    self.set_config('enabled', self.enabled)
                    self._oper_status = OperStatus.ACTIVE
                    self._update_adapter_agent()

                except Exception as e:
                    self.log.exception('read-config', e=e)
                    return fail(Failure())

            def failure(reason):
                self.log.error('hardware-sync-failed', reason=reason)

            def reschedule(_):
                delay = self.sync_tick
                delay += random.uniform(-delay / 10, delay / 10)
                self.sync_deferred = reactor.callLater(delay, self.sync_hardware)

            self.sync_deferred = self.get_nni_config()
            self.sync_deferred.addCallbacks(read_config, failure)
            self.sync_deferred.addBoth(reschedule)

    def _decode_nni_statistics(self, entry):
        # admin_status = entry.get('admin-status')
        # oper_status = entry.get('oper-status')
        # admin_status = entry.get('admin-status')
        # phys_address = entry.get('phys-address')

        stats = entry.get('statistics')
        if stats is not None:
            self.timestamp = arrow.utcnow().float_timestamp
            self.rx_bytes = int(stats.get('in-octets', 0))
            self.rx_ucast_packets = int(stats.get('in-unicast-pkts', 0))
            self.rx_bcast_packets = int(stats.get('in-broadcast-pkts', 0))
            self.rx_mcast_packets = int(stats.get('in-multicast-pkts', 0))
            self.rx_error_packets = int(stats.get('in-errors', 0)) + int(stats.get('in-discards', 0))

            self.tx_bytes = int(stats.get('out-octets', 0))
            self.tx_ucast_packets = int(stats.get('out-unicast-pkts', 0))
            self.tx_bcast_packets = int(stats.get('out-broadcast-pkts', 0))
            self.tx_mcasy_packets = int(stats.get('out-multicast-pkts', 0))
            self.tx_error_packets = int(stats.get('out-errors', 0)) + int(stats.get('out-discards', 0))

            self.rx_packets = self.rx_ucast_packets + self.rx_mcast_packets + self.rx_bcast_packets
            self.tx_packets = self.tx_ucast_packets + self.tx_mcast_packets + self.tx_bcast_packets
            # No support for rx_crc_errors or bip_errors

    def _update_statistics(self):
        if self.state == AdtnPort.State.RUNNING:
            def read_state(results):
                # self.log.debug('read-state', results=results)
                try:
                    result_dict = xmltodict.parse(results.data_xml)
                    entry = result_dict['data']['interfaces-state']['interface']
                    self._decode_nni_statistics(entry)
                    return succeed('done')

                except Exception as e:
                    self.log.exception('read-state', e=e)
                    return fail(Failure())

            def failure(reason):
                self.log.error('update-stats-failed', reason=reason)

            def reschedule(_):
                delay = self._stats_tick
                delay += random.uniform(-delay / 10, delay / 10)
                self._stats_deferred = reactor.callLater(delay, self._update_statistics)

            try:
                self._stats_deferred = self.get_nni_statistics()
                self._stats_deferred.addCallbacks(read_state, failure)
                self._stats_deferred.addBoth(reschedule)

            except Exception as e:
                self.log.exception('nni-sync', port=self.name, e=e)
                self._stats_deferred = reactor.callLater(self._stats_tick, self._update_statistics)


class MockNniPort(NniPort):
    """
    A class similar to the 'Port' class in the VOLTHA but for a non-existent (virtual OLT)

    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """

    def __init__(self, parent, **kwargs):
        super(MockNniPort, self).__init__(parent, **kwargs)

    def __str__(self):
        return "NniPort-mock-{}: Admin: {}, Oper: {}, parent: {}".format(self._port_no,
                                                                         self._admin_state,
                                                                         self._oper_status,
                                                                         self._parent)

    @staticmethod
    def get_nni_port_state_results():
        from ncclient.operations.retrieve import GetReply
        raw = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="urn:uuid:59e71979-01bb-462f-b17a-b3a45e1889ac">
          <data>
            <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
              <interface><name>hundred-gigabit-ethernet 0/1</name></interface>
            </interfaces-state>
          </data>
        </rpc-reply>
        """
        return GetReply(raw)

    @staticmethod
    def get_pon_port_state_results():
        from ncclient.operations.retrieve import GetReply
        raw = """
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="urn:uuid:59e71979-01bb-462f-b17a-b3a45e1889ac">
          <data>
            <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
              <interface><name>XPON 0/1</name></interface>
              <interface><name>XPON 0/2</name></interface>
              <interface><name>XPON 0/3</name></interface>
              <interface><name>XPON 0/4</name></interface>
              <interface><name>XPON 0/5</name></interface>
              <interface><name>XPON 0/6</name></interface>
              <interface><name>XPON 0/7</name></interface>
              <interface><name>XPON 0/8</name></interface>
              <interface><name>XPON 0/9</name></interface>
              <interface><name>XPON 0/10</name></interface>
              <interface><name>XPON 0/11</name></interface>
              <interface><name>XPON 0/12</name></interface>
              <interface><name>XPON 0/13</name></interface>
              <interface><name>XPON 0/14</name></interface>
              <interface><name>XPON 0/15</name></interface>
              <interface><name>XPON 0/16</name></interface>
            </interfaces-state>
          </data>
        </rpc-reply>
        """
        return GetReply(raw)

    def reset(self):
        """
        Set the NNI Port to a known good state on initial port startup.  Actual
        NNI 'Start' is done elsewhere
        """
        if self.state != AdtnPort.State.INITIAL:
            self.log.error('reset-ignored', state=self.state)
            return fail()

        self.log.info('resetting', label=self._label)

        # Always enable our NNI ports

        self._enabled = True
        self._admin_state = AdminState.ENABLED
        return succeed('Enabled')

    def set_config(self, leaf, value):

        if leaf == 'enabled':
            self._enabled = value
        else:
            raise NotImplemented("Leaf '{}' is not supported".format(leaf))

        return succeed('Success')
