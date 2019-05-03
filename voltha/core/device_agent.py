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
from copy import deepcopy
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.config.config_proxy import CallbackType
from voltha.protos.common_pb2 import AdminState, OperStatus, ConnectStatus, \
    OperationResp
from voltha.protos.device_pb2 import ImageDownload
from voltha.registry import registry
from voltha.protos.openflow_13_pb2 import Flows, FlowGroups, FlowChanges, \
    FlowGroupChanges


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

        self.img_dnld_proxies = {}

        self.proxy.register_callback(
            CallbackType.PRE_UPDATE, self._validate_update)
        self.proxy.register_callback(
            CallbackType.POST_UPDATE, self._process_update)

        self.flows_proxy.register_callback(
            CallbackType.PRE_UPDATE, self._pre_process_flows)

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
        self.flow_changes = None
        self.log = structlog.get_logger(device_id=initial_data.id)

    @inlineCallbacks
    def start(self, device=None, reconcile=False):
        self.log.debug('starting', device=device)
        self._set_adapter_agent()
        if device:
            # Starting from an existing data, so set the last_data
            self.last_data = device
            if reconcile:
                self.reconcile_existing_device(device)
        else:
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
        self.log.debug('reboot-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.reboot_device(device)

    def register_image_download(self, request):
        try:
            self.log.debug('register-image-download', request=request)
            path = '/devices/{}/image_downloads/{}'.format(request.id,
                                                           request.name)
            self.img_dnld_proxies[request.name] = self.core.get_proxy(path)
            self.img_dnld_proxies[request.name].register_callback(
                CallbackType.POST_UPDATE, self._update_image)
            # trigger update callback
            request.state = ImageDownload.DOWNLOAD_REQUESTED
            self.img_dnld_proxies[request.name].update('/', request)
        except Exception as e:
            self.log.exception(e.message)

    def activate_image_update(self, request):
        try:
            self.log.debug('activate-image-download', request=request)
            request.image_state = ImageDownload.IMAGE_ACTIVATE
            self.img_dnld_proxies[request.name].update('/', request)
        except Exception as e:
            self.log.exception(e.message)

    def revert_image_update(self, request):
        try:
            self.log.debug('revert-image-download', request=request)
            request.image_state = ImageDownload.IMAGE_REVERT
            self.img_dnld_proxies[request.name].update('/', request)
        except Exception as e:
            self.log.exception(e.message)

    @inlineCallbacks
    def _download_image(self, device, img_dnld):
        try:
            self.log.debug('download-image', img_dnld=img_dnld)
            yield self.adapter_agent.download_image(device, img_dnld)
        except Exception as e:
            self.log.exception(e.message)

    def get_image_download_status(self, request):
        try:
            self.log.debug('get-image-download-status',
                           request=request)
            device = self.proxy.get('/')
            return self.adapter_agent.get_image_download_status(device, request)
        except Exception as e:
            self.log.exception(e.message)
            return None

    def cancel_image_download(self, img_dnld):
        try:
            self.log.debug('cancel-image-download',
                           img_dnld=img_dnld)
            device = self.proxy.get('/')
            self.adapter_agent.cancel_image_download(device, img_dnld)
            if device.admin_state == AdminState.DOWNLOADING_IMAGE:
                device.admin_state = AdminState.ENABLED
                self.proxy.update('/', device)
                self.proxy.remove('/image_downloads/{}' \
                              .format(img_dnld.name), img_dnld)
        except Exception as e:
            self.log.exception(e.message)

    def update_device_image_download(self, img_dnld):
        try:
            self.log.debug('update-device-image-download',
                           img_dnld=img_dnld)
            self.proxy.update('/image_downloads/{}' \
                              .format(img_dnld.name), img_dnld)
        except Exception as e:
            self.log.exception(e.message)

    def unregister_device_image_download(self, name):
        try:
            self.log.debug('unregister-device-image-download',
                           name=name)
            self.self_proxies[name].unregister_callback(
                CallbackType.POST_ADD, self._download_image)
            self.self_proxies[name].unregister_callback(
                CallbackType.POST_UPDATE, self._process_image)
        except Exception as e:
            self.log.exception(e.message)

    @inlineCallbacks
    def _update_image(self, img_dnld):
        try:
            self.log.debug('update-image', img_dnld=img_dnld)
            # handle download
            if img_dnld.state == ImageDownload.DOWNLOAD_REQUESTED:
                device = self.proxy.get('/')
                yield self._download_image(device, img_dnld)
                # set back to ENABLE to be allowed to activate
                device.admin_state = AdminState.ENABLED
                self.proxy.update('/', device)
            if img_dnld.image_state == ImageDownload.IMAGE_ACTIVATE:
                device = self.proxy.get('/')
                device.admin_state = AdminState.DOWNLOADING_IMAGE
                self.proxy.update('/', device)
                yield self.adapter_agent.activate_image_update(device, img_dnld)
                device.admin_state = AdminState.ENABLED
                self.proxy.update('/', device)
            elif img_dnld.image_state == ImageDownload.IMAGE_REVERT:
                device = self.proxy.get('/')
                yield self.adapter_agent.revert_image_update(device, img_dnld)
        except Exception as e:
            self.log.exception(e.message)

    @inlineCallbacks
    def self_test(self, device, dry_run=False):
        self.log.debug('self-test-device', device=device, dry_run=dry_run)
        if not dry_run:
            result = yield self.adapter_agent.self_test(device)
            returnValue(result)

    @inlineCallbacks
    def get_device_details(self, device, dry_run=False):
        self.log.debug('get-device-details', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.get_device_details(device)

    @inlineCallbacks
    def suppress_alarm(self, filter):
        self.log.debug('suppress-alarms')
        try:
            yield self.adapter_agent.suppress_alarm(filter)
        except Exception as e:
            self.log.exception(e.message)

    @inlineCallbacks
    def unsuppress_alarm(self, filter):
        self.log.debug('unsuppress-alarms')
        try:
            yield self.adapter_agent.unsuppress_alarm(filter)
        except Exception as e:
            self.log.exception(e.message)

    @inlineCallbacks
    def reconcile_existing_device(self, device, dry_run=False):
        self.log.debug('reconcile-existing-device',
                       device=device,
                       dry_run=False)
        if not dry_run:
            yield self.adapter_agent.reconcile_device(device)

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
        self.log.debug('device-admin-states', old_state=old_admin_state,
                       new_state=new_admin_state, dry_run=dry_run)
        transition_handler = self.admin_state_fsm.get(
            (old_admin_state, new_admin_state), None)
        if transition_handler is None:
            self.log.debug('No Operation', old_state=old_admin_state,
                           new_state=new_admin_state, dry_run=dry_run)
            pass  # no-op
        elif transition_handler is False:
            raise InvalidStateTransition('{} -> {}'.format(
                old_admin_state, new_admin_state))
        else:
            assert callable(transition_handler)
            yield transition_handler(self, device, dry_run)

    @inlineCallbacks
    def _activate_device(self, device, dry_run=False):
        self.log.debug('activate-device', device=device, dry_run=dry_run)
        if not dry_run:
            device.oper_status = OperStatus.ACTIVATING
            self.update_device(device)
            yield self.adapter_agent.adopt_device(device)

    @inlineCallbacks
    def update_device(self, device):
        self.log.debug('updating-device', device=device.id)
        last_data = self.last_data
        self.last_data = device  # so that we don't propagate back
        self.proxy.update('/', device)

        # If the last device data also is enabled, active and reachable,
        # dont do anything.
        if last_data.admin_state == AdminState.ENABLED and \
                last_data.oper_status == OperStatus.ACTIVE and \
                last_data.connect_status == ConnectStatus.REACHABLE:
            self.log.info("device-status-not-changed--nothing-to-do")
            return

        if device.admin_state == AdminState.ENABLED and \
                device.oper_status == OperStatus.ACTIVE and \
                device.connect_status == ConnectStatus.REACHABLE:
            self.log.info('replay-create-interfaces ', device=device.id)
            self.core.xpon_agent.replay_interface(device.id)
            # if device accepts bulk flow update, lets just call that
            if self.device_type.accepts_bulk_flow_update:
                flows = self.flows_proxy.get('/')  # gather flows
                groups = self.groups_proxy.get('/')  # gather flow groups
                self.log.info('replay-flows ', device=device.id)
                yield self.adapter_agent.update_flows_bulk(
                    device=device,
                    flows=flows,
                    groups=groups)

    def update_device_pm_config(self, device_pm_config, init=False):
        self.callback_data = init  # so that we don't push init data
        self.pm_config_proxy.update('/', device_pm_config)

    def _propagate_change(self, device, dry_run=False):
        self.log.debug('propagate-change', device=device, dry_run=dry_run)
        if device != self.last_data:
            self.log.warn('Not-implemented-default-to-noop')
            # raise NotImplementedError()
        else:
            self.log.debug('no-op')

    def _abandon_device(self, device, dry_run=False):
        self.log.debug('abandon-device', device=device, dry_run=dry_run)
        raise NotImplementedError()

    def _delete_all_flows(self):
        """ Delete all flows on the device """
        try:
            self.flows_proxy.update('/', Flows(items=[]))
            self.groups_proxy.update('/', FlowGroups(items=[]))
        except Exception, e:
            self.exception('flow-delete-exception', e=e)

    @inlineCallbacks
    def _disable_device(self, device, dry_run=False):
        try:
            self.log.debug('disable-device', device=device, dry_run=dry_run)
            if not dry_run:
                # Remove all flows before disabling device
                # Only do this for ONUs. ponsim seems to want the flows
                # to be removed on onu disable and it does not seem to
                # hurt the real devices. Flows on OLT are not removed when
                # OLT is disabled - each adapter may do its own thing
                # for disable -e.g. OpenOLT disables the NNI interface.
                if not device.root:
                    self._delete_all_flows()
                yield self.adapter_agent.disable_device(device)
        except Exception, e:
            self.log.exception('error', e=e)

    @inlineCallbacks
    def _reenable_device(self, device, dry_run=False):
        self.log.debug('reenable-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.reenable_device(device)

    @inlineCallbacks
    def _delete_device(self, device, dry_run=False):
        self.log.debug('delete-device', device=device, dry_run=dry_run)
        if not dry_run:
            yield self.adapter_agent.delete_device(device)

    def simulate_alarm(self, device, alarm):
        try:
            self.log.debug('simulate_alarm', alarm=alarm)
            return self.adapter_agent.simulate_alarm(device, alarm)
        except Exception as e:
            self.log.exception(e.message)
            return OperationResp(code=OperationResp.OPERATION_FAILURE)

    admin_state_fsm = {

        # Missing entries yield no-op
        # False means invalid state change

        (AdminState.UNKNOWN, AdminState.ENABLED): _activate_device,

        (AdminState.PREPROVISIONED, AdminState.UNKNOWN): False,
        (AdminState.PREPROVISIONED, AdminState.ENABLED): _activate_device,
        (AdminState.PREPROVISIONED, AdminState.DOWNLOADING_IMAGE): False,

        (AdminState.ENABLED, AdminState.UNKNOWN): False,
        (AdminState.ENABLED, AdminState.ENABLED): _propagate_change,
        (AdminState.ENABLED, AdminState.DISABLED): _disable_device,
        (AdminState.ENABLED, AdminState.PREPROVISIONED): _abandon_device,

        (AdminState.DISABLED, AdminState.UNKNOWN): False,
        (AdminState.DISABLED, AdminState.PREPROVISIONED): _abandon_device,
        (AdminState.DISABLED, AdminState.ENABLED): _reenable_device,
        (AdminState.DISABLED, AdminState.DOWNLOADING_IMAGE): False,

        (AdminState.DOWNLOADING_IMAGE, AdminState.DISABLED): False

    }

    ## <======================= PM CONFIG UPDATE HANDLING ====================

    # @inlineCallbacks
    def _pm_config_updated(self, pm_configs):
        self.log.debug('pm-config-updated', pm_configs=pm_configs,
                       callback_data=self.callback_data)
        device_id = self.proxy.get('/').id
        if not self.callback_data:
            self.adapter_agent.update_adapter_pm_config(device_id, pm_configs)
        self.callback_data = None

    ## <======================= FLOW TABLE UPDATE HANDLING ====================

    def _pre_process_flows(self, flows):
        """
        This method is invoked before a device flow table data model is
        updated. If the device supports accepts_add_remove_flow_updates then it
        pre-processes the desired flows against what currently
        exist on the device to figure out which flows to delete and which
        ones to add. The resulting data is stored locally and the flow table is
        updated during the post-processing phase, i.e. via the POST_UPDATE
        callback
        :param flows: Desired flows
        :return: None
        """
        self.current_flows = self.flows_proxy.get('/')
        # self.log.debug('pre-processing-flows',
        #                logical_device_id=self.last_data.id,
        #                desired_flows=flows,
        #                existing_flows=self.current_flows)

        if self.flow_changes is None:
            self.flow_changes = FlowChanges()
        else:
            del self.flow_changes.to_add.items[:]
            del self.flow_changes.to_remove.items[:]

        current_flow_ids = set(f.id for f in self.current_flows.items)
        desired_flow_ids = set(f.id for f in flows.items)

        ids_to_add = desired_flow_ids.difference(current_flow_ids)
        ids_to_del = current_flow_ids.difference(desired_flow_ids)

        for f in flows.items:
            if f.id in ids_to_add:
                self.flow_changes.to_add.items.extend([f])

        for f in self.current_flows.items:
            if f.id in ids_to_del:
                self.flow_changes.to_remove.items.extend([f])

        self.log.debug('pre-processed-flows',
                       logical_device_id=self.last_data.id,
                       flows_to_add=len(self.flow_changes.to_add.items),
                       flows_to_remove=len(self.flow_changes.to_remove.items))


    @inlineCallbacks
    def _flow_table_updated(self, flows):
        try:
            self.log.debug('flow-table-updated',
                        logical_device_id=self.last_data.id)
            if self.flow_changes is not None and (len(self.flow_changes.to_remove.items) == 0) and (len(
                    self.flow_changes.to_add.items) == 0):
                self.log.debug('no-flow-update-required',
                            logical_device_id=self.last_data.id)
            else:

                # if device accepts non-bulk flow update, lets just call that first
                if self.device_type.accepts_add_remove_flow_updates:

                    try:
                        flow_changes = deepcopy(self.flow_changes)
                        yield self.adapter_agent.update_flows_incrementally(
                            device=self.last_data,
                            flow_changes=flow_changes,
                            group_changes=FlowGroupChanges()
                        )
                    except Exception as e:
                        self.log.exception("Failure-updating-flows", e=e)

                # if device accepts bulk flow update, lets just call that
                elif self.device_type.accepts_bulk_flow_update:
                    self.log.debug('invoking bulk')
                    groups = self.groups_proxy.get('/')  # gather flow groups
                    yield self.adapter_agent.update_flows_bulk(
                        device=self.last_data,
                        flows=flows,
                        groups=groups)
                    # add ability to notify called when an flow update completes
                    # see https://jira.opencord.org/browse/CORD-839
                else:
                    raise NotImplementedError()
        except Exception as e:
            self.log.error('error', e=e)

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
