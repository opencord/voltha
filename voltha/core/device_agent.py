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
A device agent is instantiated for each Device and plays an important role
between the Device object and its adapter.
"""
import structlog
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.config.config_proxy import CallbackType
from voltha.protos.common_pb2 import AdminState, OperStatus
from voltha.registry import registry


class InvalidStateTransition(Exception): pass


class DeviceAgent(object):

    def __init__(self, core, initial_data):

        self.core = core
        self._tmp_initial_data = initial_data
        self.last_data = None
        self.calback_data = None

        self.proxy = core.get_proxy('/devices/{}'.format(initial_data.id))
        self.flows_proxy = core.get_proxy(
            '/devices/{}/flows'.format(initial_data.id))
        self.groups_proxy = core.get_proxy(
            '/devices/{}/flow_groups'.format(initial_data.id))

        self.pm_config_proxy = core.get_proxy(
            '/devices/{}/pm_configs'.format(initial_data.id))

        self.proxy.register_callback(
            CallbackType.PRE_UPDATE, self._validate_update)
        self.proxy.register_callback(
            CallbackType.POST_UPDATE, self._process_update)

        self.flows_proxy.register_callback(
            CallbackType.POST_UPDATE, self._flow_table_updated)
        self.groups_proxy.register_callback(
            CallbackType.POST_UPDATE, self._group_table_updated)

        self.pm_config_proxy.register_callback(
            CallbackType.POST_UPDATE, self._pm_config_updated)

        # to know device capabilities
        self.device_type = core.get_proxy(
            '/device_types/{}'.format(initial_data.type)).get()

        self.adapter_agent = None
        self.log = structlog.get_logger(device_id=initial_data.id)

    @inlineCallbacks
    def start(self):
        self.log.debug('starting')
        self._set_adapter_agent()
        yield self._process_update(self._tmp_initial_data)
        del self._tmp_initial_data
        self.log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self, device):
        self.log.debug('stopping', device=device)

        # First, propagate this request to the device agents
        yield self._delete_device(device)

        self.proxy.unregister_callback(
            CallbackType.PRE_UPDATE, self._validate_update)
        self.proxy.unregister_callback(
            CallbackType.POST_UPDATE, self._process_update)
        self.log.info('stopped')

    @inlineCallbacks
    def reboot_device(self, device, dry_run=False):
        self.log.info('reboot-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.reboot_device(device)

    @inlineCallbacks
    def get_device_details(self, device, dry_run=False):
        self.log.info('get-device-details', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.get_device_details(device)

    def _set_adapter_agent(self):
        adapter_name = self._tmp_initial_data.adapter
        if adapter_name == '':
            proxy = self.core.get_proxy('/')
            known_device_types = dict(
                (dt.id, dt) for dt in proxy.get('/device_types'))
            device_type = known_device_types[self._tmp_initial_data.type]
            adapter_name = device_type.adapter
        assert adapter_name != ''
        self.adapter_agent = registry('adapter_loader').get_agent(adapter_name)

    @inlineCallbacks
    def _validate_update(self, device):
        """
        Called before each update, it allows the blocking of the update
        (by raising an exception), or even the augmentation of the incoming
        data.
        """
        self.log.debug('device-pre-update', device=device)
        yield self._process_state_transitions(device, dry_run=True)
        returnValue(device)

    @inlineCallbacks
    def _process_update(self, device):
        """
        Called after the device object was updated (individually or part of
        a transaction), and it is used to propagate the change down to the
        adapter
        """
        self.log.debug('device-post-update', device=device)

        # first, process any potential state transition
        yield self._process_state_transitions(device)

        # finally, store this data as last data so we can see what changed
        self.last_data = device

    @inlineCallbacks
    def _process_state_transitions(self, device, dry_run=False):

        old_admin_state = getattr(self.last_data, 'admin_state',
                                   AdminState.UNKNOWN)
        new_admin_state = device.admin_state
        transition_handler = self.admin_state_fsm.get(
            (old_admin_state, new_admin_state), None)
        if transition_handler is None:
            pass  # no-op
        elif transition_handler is False:
            raise InvalidStateTransition('{} -> {}'.format(
                old_admin_state, new_admin_state))
        else:
            assert callable(transition_handler)
            yield transition_handler(self, device, dry_run)

    @inlineCallbacks
    def _activate_device(self, device, dry_run=False):
        self.log.info('activate-device', device=device, dry_run=dry_run)
        if not dry_run:
            device.oper_status = OperStatus.ACTIVATING
            self.update_device(device)
            yield self.adapter_agent.adopt_device(device)

    def update_device(self, device):
        self.last_data = device  # so that we don't propagate back
        self.proxy.update('/', device)

    def update_device_pm_config(self, device_pm_config, init=False):
        self.callback_data = init# so that we don't push init data
        self.pm_config_proxy.update('/', device_pm_config)

    def _propagate_change(self, device, dry_run=False):
        self.log.info('propagate-change', device=device, dry_run=dry_run)
        if device != self.last_data:
            raise NotImplementedError()
        else:
            self.log.debug('no-op')

    def _abandon_device(self, device, dry_run=False):
        self.log.info('abandon-device', device=device, dry_run=dry_run)
        raise NotImplementedError()

    @inlineCallbacks
    def _disable_device(self, device, dry_run=False):
        self.log.info('disable-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.disable_device(device)

    @inlineCallbacks
    def _reenable_device(self, device, dry_run=False):
        self.log.info('reenable-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.reenable_device(device)

    @inlineCallbacks
    def _delete_device(self, device, dry_run=False):
        self.log.info('delete-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.delete_device(device)

    admin_state_fsm = {

        # Missing entries yield no-op
        # False means invalid state change

        (AdminState.UNKNOWN, AdminState.ENABLED): _activate_device,

        (AdminState.PREPROVISIONED, AdminState.UNKNOWN): False,
        (AdminState.PREPROVISIONED, AdminState.ENABLED): _activate_device,

        (AdminState.ENABLED, AdminState.UNKNOWN): False,
        (AdminState.ENABLED, AdminState.ENABLED): _propagate_change,
        (AdminState.ENABLED, AdminState.DISABLED): _disable_device,
        (AdminState.ENABLED, AdminState.PREPROVISIONED): _abandon_device,

        (AdminState.DISABLED, AdminState.UNKNOWN): False,
        (AdminState.DISABLED, AdminState.PREPROVISIONED): _abandon_device,
        (AdminState.DISABLED, AdminState.ENABLED): _reenable_device

    }

    ## <======================= PM CONFIG UPDATE HANDLING ====================

    #@inlineCallbacks
    def _pm_config_updated(self, pm_configs):
        self.log.debug('pm-config-updated', pm_configs=pm_configs,
                       callback_data=self.callback_data)
        device_id = self.proxy.get('/').id
        if not self.callback_data:
            self.adapter_agent.update_adapter_pm_config(device_id, pm_configs)
        self.callback_data = None

    ## <======================= FLOW TABLE UPDATE HANDLING ====================

    @inlineCallbacks
    def _flow_table_updated(self, flows):
        self.log.debug('flow-table-updated',
                  logical_device_id=self.last_data.id, flows=flows)

        # if device accepts bulk flow update, lets just call that
        if self.device_type.accepts_bulk_flow_update:
            groups = self.groups_proxy.get('/') # gather flow groups
            yield self.adapter_agent.update_flows_bulk(
                device=self.last_data,
                flows=flows,
                groups=groups)
            # add ability to notify called when an flow update completes
            # see https://jira.opencord.org/browse/CORD-839

        elif self.device_type.accepts_add_remove_flow_updates:
            raise NotImplementedError()

        else:
            raise NotImplementedError()

    ## <======================= GROUP TABLE UPDATE HANDLING ===================

    @inlineCallbacks
    def _group_table_updated(self, groups):
        self.log.debug('group-table-updated',
                  logical_device_id=self.last_data.id,
                  flow_groups=groups)

        # if device accepts bulk flow update, lets just call that
        if self.device_type.accepts_bulk_flow_update:
            flows = self.flows_proxy.get('/')  # gather flows
            yield self.adapter_agent.update_flows_bulk(
                device=self.last_data,
                flows=flows,
                groups=groups)
            # add ability to notify called when an group update completes
            # see https://jira.opencord.org/browse/CORD-839

        elif self.device_type.accepts_add_remove_flow_updates:
            raise NotImplementedError()

        else:
            raise NotImplementedError()

