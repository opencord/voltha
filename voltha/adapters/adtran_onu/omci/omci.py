# Copyright 2018-present Adtran, Inc.
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
from twisted.internet.defer import inlineCallbacks, returnValue, TimeoutError
from twisted.internet import reactor

from voltha.protos.device_pb2 import Image

from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.extensions.omci.onu_configuration import OMCCVersion

from omci_entities import onu_custom_me_entities
from voltha.extensions.omci.omci_me import *

_STARTUP_RETRY_WAIT = 5
# abbreviations
OP = EntityOperations


class OMCI(object):
    """
    OpenOMCI Support
    """
    DEFAULT_UNTAGGED_VLAN = 4091      # To be equivalent to BroadCom Defaults

    def __init__(self, handler, omci_agent):
        self.log = structlog.get_logger(device_id=handler.device_id)
        self._handler = handler
        self._openomci_agent = omci_agent
        self._enabled = False
        self._connected = False
        self._deferred = None
        self._bridge_initialized = False
        self._in_sync_reached = False
        self._omcc_version = OMCCVersion.Unknown
        self._total_tcont_count = 0                    # From ANI-G ME
        self._qos_flexibility = 0                      # From ONT2_G ME

        self._in_sync_subscription = None
        self._connectivity_subscription = None
        self._capabilities_subscription = None

        # self._service_downloaded = False
        self._mib_downloaded = False
        self._mib_download_task = None
        self._mib_download_deferred = None

        self._onu_omci_device = omci_agent.add_device(handler.device_id,
                                                      handler.adapter_agent,
                                                      custom_me_map=onu_custom_me_entities(),
                                                      support_classes=handler.adapter.adtran_omci)

    def __str__(self):
        return "OMCI"

    @property
    def omci_agent(self):
        return self._openomci_agent

    @property
    def omci_cc(self):
        # TODO: Decrement access to Communications channel at this point?  What about current PM stuff?
        return self.onu_omci_device.omci_cc if self._onu_omci_device is not None else None

    def receive_message(self, msg):
        if self.enabled:
            # TODO: Have OpenOMCI actually receive the messages
            self.omci_cc.receive_message(msg)

    def _start(self):
        self._cancel_deferred()

        # Subscriber to events of interest in OpenOMCI
        self._subscribe_to_events()
        self._onu_omci_device.start()

        device = self._handler.adapter_agent.get_device(self._handler.device_id)
        device.reason = 'Performing MIB Upload'
        self._handler.adapter_agent.update_device(device)

        if self._onu_omci_device.mib_db_in_sync:
            self._deferred = reactor.callLater(0, self._mib_in_sync)

    def _stop(self):
        self._cancel_deferred()

        # Unsubscribe to OpenOMCI Events
        self._unsubscribe_to_events()
        self._onu_omci_device.stop()        # Will also cancel any running tasks/state-machines

        self._mib_downloaded = False
        self._mib_download_task = None
        self._bridge_initialized = False
        self._in_sync_reached = False

    def _cancel_deferred(self):
        d1, self._deferred = self._deferred, None
        d2, self._mib_download_deferred = self._mib_download_deferred, None

        for d in [d1, d2]:
            try:
                if d is not None and not d.called:
                    d.cancel()
            except:
                pass

    def delete(self):
        self.enabled = False

        agent, self._openomci_agent = self._openomci_agent, None
        device_id = self._handler.device_id
        self._onu_omci_device = None
        self._handler = None

        if agent is not None:
            agent.remove_device(device_id, cleanup=True)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        if self._enabled != value:
            self._enabled = value

            if value:
                self._start()
            else:
                self._stop()

    @property
    def connected(self):
        return self._connected

    @property
    def onu_omci_device(self):
        return self._onu_omci_device

    def set_pm_config(self, pm_config):
        """
        Set PM interval configuration

        :param pm_config: (OnuPmIntervalMetrics) PM Interval configuration
        :return:
        """
        self.onu_omci_device.set_pm_config(pm_config)

    def _mib_in_sync(self):
        """
        This method is ran whenever the ONU MIB database is in-sync. This is often after
        the initial MIB Upload during ONU startup, or after it has gone out-of-sync and
        then back in. This second case could be due a reboot of the ONU and a new version
        of firmware is running on the ONU hardware.
        """
        self.log.info('mib-in-sync')

        device = self._handler.adapter_agent.get_device(self._handler.device_id)
        device.oper_status = OperStatus.ACTIVE
        device.connect_status = ConnectStatus.REACHABLE
        device.reason = ''
        self._handler.adapter_agent.update_device(device)

        omci_dev = self._onu_omci_device
        config = omci_dev.configuration

        # In Sync, we can register logical ports now. Ideally this could occur on
        # the first time we received a successful (no timeout) OMCI Rx response.
        try:
            device = self._handler.adapter_agent.get_device(self._handler.device_id)

            ani_g = config.ani_g_entities
            uni_g = config.uni_g_entities
            pon_ports = len(ani_g) if ani_g is not None else 0
            uni_ports = len(uni_g) if uni_g is not None else 0

            # For the UNI ports below, they are created after the MIB Sync event occurs
            # and the onu handler adds the ONU
            assert pon_ports == 1, 'Expected one PON/ANI port, got {}'.format(pon_ports)
            assert uni_ports == len(self._handler.uni_ports), \
                'Expected {} UNI port(s), got {}'.format(len(self._handler.uni_ports), uni_ports)

            # serial_number = omci_dev.configuration.serial_number
            # self.log.info('serial-number', serial_number=serial_number)

            # Save entity_id of PON ports
            self._handler.pon_ports[0].entity_id = ani_g.keys()[0]

            self._total_tcont_count = ani_g.get('total-tcont-count')
            self._qos_flexibility = config.qos_configuration_flexibility or 0
            self._omcc_version = config.omcc_version or OMCCVersion.Unknown

            # vendorProductCode = str(config.vendor_product_code or 'unknown').rstrip('\0')

            host_info = omci_dev.query_mib(IpHostConfigData.class_id)
            mgmt_mac_address = next((host_info[inst].get('attributes').get('mac_address')
                                     for inst in host_info
                                     if isinstance(inst, int)), 'unknown')
            device.mac_address = str(mgmt_mac_address)
            device.model = str(config.version or 'unknown').rstrip('\0')

            equipment_id = config.equipment_id or " unknown    unknown "
            eqpt_boot_version = str(equipment_id).rstrip('\0')
            # eqptId = eqpt_boot_version[:10]         # ie) BVMDZ10DRA
            boot_version = eqpt_boot_version[12:]     # ie) CML.D55~

            images = [Image(name='boot-code',
                            version=boot_version.rstrip('\0'),
                            is_active=False,
                            is_committed=True,
                            is_valid=True,
                            install_datetime='Not Available',
                            hash='Not Available')] + \
                config.software_images

            del (device.images.image[:])       # Clear previous entries
            device.images.image.extend(images)

            # Save our device information
            self._handler.adapter_agent.update_device(device)

            # Start MIB download  TODO: This will be replaced with a MIB Download task soon
            self._in_sync_reached = True

        except Exception as e:
            self.log.exception('device-info-load', e=e)
            self._deferred = reactor.callLater(_STARTUP_RETRY_WAIT, self._mib_in_sync)

    def _subscribe_to_events(self):
        from voltha.extensions.omci.onu_device_entry import OnuDeviceEvents, \
            OnuDeviceEntry
        from voltha.extensions.omci.omci_cc import OMCI_CC, OmciCCRxEvents

        # OMCI MIB Database sync status
        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self._handler.device_id,
                                               OnuDeviceEvents.MibDatabaseSyncEvent)
        self._in_sync_subscription = bus.subscribe(topic, self.in_sync_handler)

        # OMCI Capabilities (MEs and Message Types
        bus = self._onu_omci_device.event_bus
        topic = OnuDeviceEntry.event_bus_topic(self._handler.device_id,
                                               OnuDeviceEvents.OmciCapabilitiesEvent)
        self._capabilities_subscription = bus.subscribe(topic, self.capabilities_handler)

        # OMCI-CC Connectivity Events (for reachability/heartbeat)
        bus = self._onu_omci_device.omci_cc.event_bus
        topic = OMCI_CC.event_bus_topic(self._handler.device_id,
                                        OmciCCRxEvents.Connectivity)
        self._connectivity_subscription = bus.subscribe(topic, self.onu_is_reachable)

        # TODO: Watch for any MIB RESET events or detection of an ONU reboot.
        #       If it occurs, set _service_downloaded and _mib_download to false
        #       and make sure that we get 'new' capabilities

    def _unsubscribe_to_events(self):
        insync, self._in_sync_subscription = self._in_sync_subscription, None
        connect, self._connectivity_subscription = self._connectivity_subscription, None
        caps, self._capabilities_subscription = self._capabilities_subscription, None

        if insync is not None:
            bus = self._onu_omci_device.event_bus
            bus.unsubscribe(insync)

        if connect is not None:
            bus = self._onu_omci_device.omci_cc.event_bus
            bus.unsubscribe(connect)

        if caps is not None:
            bus = self._onu_omci_device.event_bus
            bus.unsubscribe(caps)

    def in_sync_handler(self, _topic, msg):
        if self._in_sync_subscription is not None:
            try:
                from voltha.extensions.omci.onu_device_entry import IN_SYNC_KEY

                if msg[IN_SYNC_KEY]:
                    # Start up device_info load from MIB DB
                    reactor.callLater(0, self._mib_in_sync)
                else:
                    # Cancel any running/scheduled MIB download task
                    try:
                        d, self._mib_download_deferred = self._mib_download_deferred, None
                        d.cancel()
                    except:
                        pass

            except Exception as e:
                self.log.exception('in-sync', e=e)

    def capabilities_handler(self, _topic, _msg):
        """
        This event occurs after an ONU reaches the In-Sync state and the OMCI ME has
        been queried for supported ME and message types.

        At this point, we can act upon any download device and/or service Technology
        profiles (when they exist).  For now, just run our somewhat fixed script
        """
        if self._capabilities_subscription is not None:
            from adtn_mib_download_task import AdtnMibDownloadTask
            self._mib_download_task = None

            def success(_results):
                dev = self._handler.adapter_agent.get_device(self._handler.device_id)
                dev.reason = ''
                self._handler.adapter_agent.update_device(dev)
                self._mib_downloaded = True
                self._mib_download_task = None

            def failure(reason):
                self.log.error('mib-download-failure', reason=reason)
                self._mib_download_task = None
                dev = self._handler.adapter_agent.get_device(self._handler.device_id)
                self._handler.adapter_agent.update_device(dev)
                self._mib_download_deferred = reactor.callLater(_STARTUP_RETRY_WAIT,
                                                                self.capabilities_handler,
                                                                None, None)
            if not self._mib_downloaded:
                device = self._handler.adapter_agent.get_device(self._handler.device_id)
                device.reason = 'Initial MIB Download'
                self._handler.adapter_agent.update_device(device)
                self._mib_download_task = AdtnMibDownloadTask(self.omci_agent,
                                                              self._handler)

            # TODO: Remove later.  Service specific ME download is now done as part of the
            #                      Technology Profile setup
            # elif not self._service_downloaded:
            #     device = self._handler.adapter_agent.get_device(self._handler.device_id)
            #     device.reason = 'Initial Service Download'
            #     self._handler.adapter_agent.update_device(device)
            #     self._mib_download_task = AdtnServiceDownloadTask(self.omci_agent,
            #                                                       self._handler)
            if self._mib_download_task is not None:
                self._mib_download_deferred = \
                    self._onu_omci_device.task_runner.queue_task(self._mib_download_task)
                self._mib_download_deferred.addCallbacks(success, failure)

    def onu_is_reachable(self, _topic, msg):
        """
        Reach-ability change event
        :param _topic: (str) subscription topic, not used
        :param msg: (dict) 'connected' key holds True if reachable
        """
        from voltha.extensions.omci.omci_cc import CONNECTED_KEY
        if self._connectivity_subscription is not None:
            try:
                connected = msg[CONNECTED_KEY]

                # TODO: For now, only care about the first connect occurrence.
                # Later we could use this for a heartbeat, but may want some hysteresis
                # Cancel any 'reachable' subscriptions
                if connected:
                    evt_bus = self._onu_omci_device.omci_cc.event_bus
                    evt_bus.unsubscribe(self._connectivity_subscription)
                    self._connectivity_subscription = None
                    self._connected = True

                    device = self._handler.adapter_agent.get_device(self._handler.device_id)
                    device.oper_status = OperStatus.ACTIVE
                    device.connect_status = ConnectStatus.REACHABLE
                    self._handler.adapter_agent.update_device(device)

            except Exception as e:
                self.log.exception('onu-reachable', e=e)
