# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import structlog
from enum import Enum
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, succeed

from voltha.protos.common_pb2 import OperStatus, AdminState


class AdtnPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    """
    class State(Enum):
        INITIAL = 0  # Created and initialization in progress
        RUNNING = 1  # PON port contacted, ONU discovery active
        STOPPED = 2  # Disabled
        DELETING = 3  # Cleanup

    _SUPPORTED_ACTIVATION_METHODS = ['autodiscovery']  # , 'autoactivate']
    _SUPPORTED_AUTHENTICATION_METHODS = ['serial-number']

    def __init__(self, parent, **kwargs):
        assert parent, 'parent is None'
        assert 'port_no' in kwargs, 'Port number not found'

        self.log = structlog.get_logger(device_id=parent.device_id)

        self._parent = parent
        self._port_no = kwargs.get('port_no')

        # Set the following in your derived class
        self._name = None
        self._label = None
        self._port = None

        self.sync_tick = 20.0
        self.sync_deferred = None  # For sync of PON config to hardware

        # TODO: Deprecate 'enabled' and use admin_state instead
        self._enabled = False
        self._admin_state = AdminState.DISABLED
        self._oper_status = OperStatus.DISCOVERED
        self._state = AdtnPort.State.INITIAL

        self.deferred = None  # General purpose

        # Statistics
        self.rx_packets = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.tx_bytes = 0

    def __del__(self):
        self.stop()

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        raise NotImplementedError('Add to your derived class')

    @property
    def port_no(self):
        return self._port_no

    @property
    def name(self):
        return self._name

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def olt(self):
        return self._parent

    @property
    def admin_state(self):
        return self._admin_state

    @admin_state.setter
    def admin_state(self, value):
        if self._admin_state != value:
            self._admin_state = value
            if self._admin_state == AdminState.ENABLED:
                self.start()
            else:
                self.stop()
    @property
    def enabled(self):
        return self._admin_state == AdminState.ENABLED

    @enabled.setter
    def enabled(self, value):
        assert isinstance(value, bool), 'enabled is a boolean'
        self.admin_state = AdminState.ENABLED if value else AdminState.DISABLED

    # @property
    # def enabled(self):
    #     return self._enabled
    #
    # @enabled.setter
    # def enabled(self, value):
    #     assert isinstance(value, bool), 'enabled is a boolean'
    #     if self._enabled != value:
    #         if value:
    #             self.start()
    #         self.stop()

    @property
    def oper_status(self):
        return self._oper_status

    @property
    def adapter_agent(self):
        return self.olt.adapter_agent

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port. For PON ports, a logical port
        is not currently created, so always return None

        :return: VOLTHA logical port or None if not supported
        """
        return None

    def cancel_deferred(self):
        d1, self.deferred = self.deferred, None
        d2, self.sync_deferred = self.sync_deferred, None

        for d in [d1, d2]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except Exception:
                pass

    def _update_adapter_agent(self):
        raise NotImplementedError('Add to your derived class')

    def start(self):
        """
        Start/enable this PON and start ONU discover
        """
        if self.state == AdtnPort.State.RUNNING:
            return succeed('Running')

        self.log.info('start-port')

        self.cancel_deferred()
        self.state = AdtnPort.State.INITIAL
        self._oper_status = OperStatus.ACTIVATING
        self._enabled = True

        # Do the rest of the startup in an async method
        self.deferred = reactor.callLater(0.5, self.finish_startup)
        self._update_adapter_agent()

        return succeed('Scheduled')

    def finish_startup(self):
        if self.state == AdtnPort.State.INITIAL:
            self.log.debug('final-startup')

            # If here, initial settings were successfully written to hardware

            self._enabled = True
            self._admin_state = AdminState.ENABLED
            self._oper_status = OperStatus.ACTIVE  # TODO: is this correct, how do we tell GRPC
            self.state = AdtnPort.State.RUNNING

            self.sync_deferred = reactor.callLater(self.sync_tick,
                                                   self.sync_hardware)
            self._update_adapter_agent()

    @inlineCallbacks
    def stop(self):
        if self.state == AdtnPort.State.STOPPED:
            self.log.debug('already stopped')
            returnValue('Stopped')

        self.log.info('stopping')
        try:
            self.cancel_deferred()
            self._enabled = False
            self._admin_state = AdminState.DISABLED
            self._oper_status = OperStatus.UNKNOWN
            self._update_adapter_agent()

            self.state = AdtnPort.State.STOPPED

            self.sync_deferred = reactor.callLater(self.sync_tick,
                                                   self.sync_hardware)

            self.deferred = self.finish_stop()
            yield self.deferred

        except Exception as e:
            raise

        returnValue('Stopped')

    def finish_stop(self):
        pass   # Add to your derived class if needed

    def restart(self):
        if self.state == AdtnPort.State.RUNNING or self.state == AdtnPort.State.STOPPED:
            start_it = (self.state == AdtnPort.State.RUNNING)
            self.state = AdtnPort.State.INITIAL
            return self.start() if start_it else self.stop()
        return succeed('nop')

    def delete(self):
        """
        Parent device is being deleted. Do not change any config but
        stop all polling
        """
        self.log.info('Deleting')
        self.state = AdtnPort.State.DELETING
        self.cancel_deferred()

    def sync_hardware(self):
        raise NotImplementedError('Add to your derived class')

# TODO: Continue to consolidate port functionality
