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

import structlog
import xmltodict
from enum import Enum
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, succeed, fail
from twisted.python.failure import Failure
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port


class NniPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """
    class State(Enum):
        INITIAL = 0   # Created and initialization in progress
        RUNNING = 1   # PON port contacted, ONU discovery active
        STOPPED = 2   # Disabled
        DELETING = 3  # Cleanup

    def __init__(self, parent, **kwargs):
        # TODO: Weed out those properties supported by common 'Port' object
        assert parent, 'parent is None'
        assert 'port_no' in kwargs, 'Port number not found'

        self.log = structlog.get_logger(port_no=kwargs.get('port_no'))
        self.log.info('creating')

        self._port_no = kwargs.get('port_no')
        self._name = kwargs.get('name', 'nni-{}'.format(self._port_no))
        self._port = None
        self._logical_port = None
        self._parent = parent

        self._sync_tick = 20.0      # TODO: Implement
        self._sync_deferred = None

        self._deferred = None
        self._state = NniPort.State.INITIAL

        # Local cache of NNI configuration

        self._enabled = None
        self._ianatype = '<type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">ianaift:ethernetCsmacd</type>'

        # And optional parameters
        # TODO: Currently cannot update admin/oper status, so create this enabled and active
        # self._admin_state = kwargs.pop('admin_state', AdminState.UNKNOWN)
        # self._oper_status = kwargs.pop('oper_status', OperStatus.UNKNOWN)
        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE

        self._label = kwargs.pop('label', 'NNI port {}'.format(self._port_no))
        self._mac_address = kwargs.pop('mac_address', '00:00:00:00:00:00')
        # TODO: Get with JOT and find out how to pull out MAC Address via NETCONF
        # TODO: May need to refine capabilities into current, advertised, and peer

        self._ofp_capabilities = kwargs.pop('ofp_capabilities', OFPPF_100GB_FD | OFPPF_FIBER)
        self._ofp_state = kwargs.pop('ofp_state', OFPPS_LIVE)
        self._current_speed = kwargs.pop('current_speed', OFPPF_100GB_FD)
        self._max_speed = kwargs.pop('max_speed', OFPPF_100GB_FD)
        self._device_port_no = kwargs.pop('device_port_no', self._port_no)

    def __del__(self):
        self.stop()

    def __str__(self):
        return "NniPort-{}: Admin: {}, Oper: {}, parent: {}".format(self._port_no,
                                                                    self._admin_state,
                                                                    self._oper_status,
                                                                    self._parent)

    @property
    def port_number(self):
        return self._port_no

    @property
    def name(self):
        return self._name

    @property
    def olt(self):
        return self._parent

    @property
    def state(self):
        return self._state

    @property
    def adapter_agent(self):
        return self.olt.adapter_agent

    @property
    def iana_type(self):
        return self._ianatype

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        assert isinstance(value, bool), 'enabled is a boolean'
        if self._enabled != value:
            if value:
                self.start()
            self.stop()

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._sync_deferred = self._sync_deferred, None
        for d in [d1, d2]:
            try:
                if d is not None and d.called:
                    d.cancel()
            except:
                pass

    def _update_adapter_agent(self):
        # TODO: Currently the adapter_agent does not allow 'update' of port status
        # self.adapter_agent.update_port(self.olt.device_id, self.get_port())
        pass

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self._port is None:
            self._port = Port(port_no=self._port_no,
                              label=self._label,
                              type=Port.ETHERNET_NNI,
                              admin_state=self._admin_state,
                              oper_status=self._oper_status)
        return self._port

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port
        :return: VOLTHA logical port or None if not supported
        """
        if self._logical_port is None:
            openflow_port = ofp_port(port_no=self._port_no,
                                     hw_addr=mac_str_to_tuple(self._mac_address),
                                     name=self._name,
                                     config=0,
                                     state=self._ofp_state,
                                     curr=self._ofp_capabilities,
                                     advertised=self._ofp_capabilities,
                                     peer=self._ofp_capabilities,
                                     curr_speed=self._current_speed,
                                     max_speed=self._max_speed)

            self._logical_port = LogicalPort(id='nni{}'.format(self._port_no),
                                             ofp_port=openflow_port,
                                             device_id=self._parent.device_id,
                                             device_port_no=self._device_port_no,
                                             root_port=True)
        return self._logical_port

    def start(self):
        """
        Start/enable this NNI
        
        :return: (deferred)
        """
        if self._state == NniPort.State.RUNNING:
            return succeed('Running')

        self.log.info('starting')
        self._cancel_deferred()

        self._oper_status = OperStatus.ACTIVATING
        self._update_adapter_agent()

        # Do the rest of the startup in an async method
        self._deferred = reactor.callLater(0, self._finish_startup)
        return succeed('Scheduled')

    @inlineCallbacks
    def _finish_startup(self):
        if self._state != NniPort.State.INITIAL:
            returnValue('Done')

        self._enabled = True
        self._admin_state = AdminState.ENABLED
        self._oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC
        self._update_adapter_agent()

        try:
            results = yield self.set_config('enabled', True)

        except Exception as e:
            self.log.exception('nni-start', e=e)
            self._admin_state = AdminState.UNKNOWN
            raise

        # TODO: Start status polling of NNI interfaces
        self._deferred = None  # = reactor.callLater(3, self.do_stuff)
        self._state = NniPort.State.RUNNING
        # Begin hardware sync
        self._sync_deferred = reactor.callLater(self._sync_tick, self._sync_hardware)

        returnValue(self._deferred)

    @inlineCallbacks
    def stop(self):
        if self._state == NniPort.State.STOPPED:
            returnValue(succeed('Stopped'))

        self.log.info('stopping')
        self._cancel_deferred()

        # NOTE: Leave all NNI ports active (may have inband management)
        # TODO: Revisit leaving NNI Ports active on disable

        # Flush config cache
        self._enabled = None

        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.UNKNOWN
        self._update_adapter_agent()

        try:
            results = yield self.set_config('enabled', False)

        except Exception as e:
            self.log.exception('nni-stop', e=e)
            self._admin_state = AdminState.UNKNOWN
            raise

        self._state = NniPort.State.STOPPED
        returnValue(self._deferred)

    def restart(self):
        if self._state == NniPort.State.RUNNING or self._state == NniPort.State.STOPPED:
            start_it = (self._state == NniPort.State.RUNNING)
            self._state = NniPort.State.INITIAL
            return self.start() if start_it else self.stop()
        return succeed('nop')

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('deleting', label=self._label)
        self._state = NniPort.State.DELETING
        self._cancel_deferred()

    @inlineCallbacks
    def reset(self):
        """
        Set the NNI Port to a known good state on initial port startup.  Actual
        NNI 'Start' is done elsewhere
        """
        if self._state != NniPort.State.INITIAL:
            self.log.error('reset-ignored', state=self._state)
            returnValue('Ignored')

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
                 '  <name>{}</name>'.format(self._name) + \
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
                 '   <name>{}</name>'.format(self._name) + \
                 '   <enabled/>' + \
                 '  </interface>' + \
                 ' </interfaces>' + \
                 '</filter>'
        return self._parent.netconf_client.get(config)

    def _sync_hardware(self):
        if self._state == NniPort.State.RUNNING or self._state == NniPort.State.STOPPED:
            def read_config(results):
                self.log.debug('read-config', results=results)
                try:
                    result_dict = xmltodict.parse(results.data_xml)
                    entries = result_dict['data']['interfaces']['interface']

                    enabled = entries.get('enabled',
                                          str(not self.enabled).lower()) == 'true'

                    return succeed('in-sync') if self.enabled == enabled else \
                        self.set_config('enabled', self.enabled)

                except Exception as e:
                    self.log.exception('read-config', e=e)
                    return fail(Failure())

            def failure(reason):
                self.log.error('hardware-sync-failed', reason=reason)

            def reschedule(_):
                delay = self._sync_tick
                delay += random.uniform(-delay / 10, delay / 10)
                self._sync_deferred = reactor.callLater(delay, self._sync_hardware)

            self._sync_deferred = self.get_nni_config()
            self._sync_deferred.addCallbacks(read_config, failure)
            self._sync_deferred.addBoth(reschedule)


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

    def reset(self):
        """
        Set the NNI Port to a known good state on initial port startup.  Actual
        NNI 'Start' is done elsewhere
        """
        if self._state != NniPort.State.INITIAL:
            self.log.error('reset-ignored', state=self._state)
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
