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
#
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, TimeoutError, failure
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.tasks.task import Task
from voltha.extensions.omci.omci_defs import *

OP = EntityOperations
RC = ReasonCodes


class MibDownloadFailure(Exception):
    """
    This error is raised by default when the download fails
    """


class MibResourcesFailure(Exception):
    """
    This error is raised by when one or more resources required is not available
    """


class AdtnMibDownloadTask(Task):
    """
    OpenOMCI MIB Download Example

    This task takes the legacy OMCI 'script' for provisioning the Adtran ONU
    and converts it to run as a Task on the OpenOMCI Task runner.  This is
    in order to begin to decompose service instantiation in preparation for
    Technology Profile work.

    Once technology profiles are ready, some of this task may hang around or
    be moved into OpenOMCI if there are any very common settings/configs to do
    for any profile that may be provided in the v2.0 release

    Currently, the only service tech profiles expected by v2.0 will be for AT&T
    residential data service and DT residential data service.
    """
    task_priority = Task.DEFAULT_PRIORITY + 10
    default_tpid = 0x8100
    default_gem_payload = 1518

    name = "ADTRAN MIB Download Task"

    def __init__(self, omci_agent, handler):
        """
        Class initialization

        :param omci_agent: (OpenOMCIAgent) OMCI Adapter agent
        :param handler: (OnuHandler) ONU Device Handler
        """
        super(AdtnMibDownloadTask, self).__init__(AdtnMibDownloadTask.name,
                                                  omci_agent,
                                                  handler.device_id,
                                                  priority=AdtnMibDownloadTask.task_priority,
                                                  exclusive=False)
        self._handler = handler
        self._onu_device = omci_agent.get_device(handler.device_id)
        self._local_deferred = None

        # Frame size
        self._max_gem_payload = AdtnMibDownloadTask.default_gem_payload

        # Port numbers
        self._pon_port_num = 0
        self._uni_port_num = 0  # TODO Both port numbers are the same, is this correct?  See MacBridgePortConfigurationDataFrame

        self._pon = handler.pon_port()
        self._vlan_tcis_1 = self._handler.vlan_tcis_1

        # Entity IDs. IDs with values can probably be most anything for most ONUs,
        #             IDs set to None are discovered/set
        #
        # TODO: Probably need to store many of these in the appropriate object (UNI, PON,...)
        #
        self._ieee_mapper_service_profile_entity_id = self._pon.ieee_mapper_service_profile_entity_id
        self._mac_bridge_port_ani_entity_id = self._pon.mac_bridge_port_ani_entity_id
        self._gal_enet_profile_entity_id = self._handler.gal_enet_profile_entity_id

        # Next to are specific     TODO: UNI lookups here or uni specific install !!!
        self._ethernet_uni_entity_id = self._handler.uni_ports[0].entity_id
        self._mac_bridge_service_profile_entity_id = \
            self._handler.mac_bridge_service_profile_entity_id

    def cancel_deferred(self):
        super(AdtnMibDownloadTask, self).cancel_deferred()

        d, self._local_deferred = self._local_deferred, None
        try:
            if d is not None and not d.called:
                d.cancel()
        except:
            pass

    def start(self):
        """
        Start the MIB Download
        """
        super(AdtnMibDownloadTask, self).start()
        self._local_deferred = reactor.callLater(0, self.perform_mib_download)

    def stop(self):
        """
        Shutdown MIB Synchronization tasks
        """
        self.log.debug('stopping')

        self.cancel_deferred()
        super(AdtnMibDownloadTask, self).stop()

    def check_status_and_state(self, results, operation=''):
        """
        Check the results of an OMCI response.  An exception is thrown
        if the task was cancelled or an error was detected.

        :param results: (OmciFrame) OMCI Response frame
        :param operation: (str) what operation was being performed
        :return: True if successful, False if the entity existed (already created)
        """
        omci_msg = results.fields['omci_message'].fields
        status = omci_msg['success_code']
        error_mask = omci_msg.get('parameter_error_attributes_mask', 'n/a')
        failed_mask = omci_msg.get('failed_attributes_mask', 'n/a')
        unsupported_mask = omci_msg.get('unsupported_attributes_mask', 'n/a')

        self.log.debug(operation, status=status, error_mask=error_mask,
                       failed_mask=failed_mask, unsupported_mask=unsupported_mask)

        if status == RC.Success:
            self.strobe_watchdog()
            return True

        elif status == RC.InstanceExists:
            return False

        raise MibDownloadFailure('{} failed with a status of {}, error_mask: {}, failed_mask: {}, unsupported_mask: {}'
                                 .format(operation, status, error_mask, failed_mask, unsupported_mask))

    @inlineCallbacks
    def perform_mib_download(self):
        """
        Send the commands to minimally configure the PON, Bridge, and
        UNI ports for this device. The application of any service flows
        and other characteristics are done once resources (gem-ports, tconts, ...)
        have been defined.
        """
        self.log.info('perform-initial-download')

        device = self._handler.adapter_agent.get_device(self.device_id)

        def resources_available():
            return len(self._handler.uni_ports) > 0

        if self._handler.enabled and resources_available():
            device.reason = 'Performing Initial OMCI Download'
            self._handler.adapter_agent.update_device(device)

            try:
                # Lock the UNI ports to prevent any alarms during initial configuration
                # of the ONU
                for uni_port in self._handler.uni_ports:
                    self.strobe_watchdog()

                    yield self.enable_uni(uni_port, True)

                    # Provision the initial bridge configuration
                    yield self.perform_initial_bridge_setup(uni_port)

                    # And re-enable the UNIs if needed
                    yield self.enable_uni(uni_port, False)

                    # If here, we are done with the generic MIB download
                    device = self._handler.adapter_agent.get_device(self.device_id)

                    device.reason = 'Initial OMCI Download Complete'
                    self._handler.adapter_agent.update_device(device)
                    self.deferred.callback('MIB Download - success')

            except TimeoutError as e:
                self.deferred.errback(failure.Failure(e))

        else:
            # TODO: Provide better error reason, what was missing...
            e = MibResourcesFailure('ONU is not enabled')
            self.deferred.errback(failure.Failure(e))

    @inlineCallbacks
    def perform_initial_bridge_setup(self, uni_port):
        omci_cc = self._onu_device.omci_cc
        frame = None

        try:
            ################################################################################
            # Common - PON and/or UNI                                                      #
            ################################################################################
            # MAC Bridge Service Profile
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data (PON & UNI)
            #  References:
            #            - Nothing
            attributes = {
                'spanning_tree_ind': False,
                'learning_ind': True
            }
            frame = MacBridgeServiceProfileFrame(
                self._mac_bridge_service_profile_entity_id,
                attributes
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-service-profile')

            ################################################################################
            # PON Specific                                                                 #
            ################################################################################
            # IEEE 802.1 Mapper Service config - Once per PON
            #
            #  EntityID will be referenced by:
            #            - MAC Bridge Port Configuration Data for the PON port
            #  References:
            #            - Nothing at this point. When a GEM port is created, this entity will
            #              be updated to reference the GEM Interworking TP

            frame = Ieee8021pMapperServiceProfileFrame(self._ieee_mapper_service_profile_entity_id +
                                                       uni_port.mac_bridge_port_num).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-8021p-mapper-service-profile')

            ################################################################################
            # Create MAC Bridge Port Configuration Data for the PON port via IEEE 802.1
            # mapper service. Upon receipt by the ONU, the ONU will create an instance
            # of the following before returning the response.
            #
            #     - MAC bridge port designation data
            #     - MAC bridge port filter table data
            #     - MAC bridge port bridge table data
            #
            #  EntityID will be referenced by:
            #            - Implicitly by the VLAN tagging filter data
            #  References:
            #            - MAC Bridge Service Profile (the bridge)
            #            - IEEE 802.1p mapper service profile for PON port

            frame = MacBridgePortConfigurationDataFrame(
                self._mac_bridge_port_ani_entity_id,                    # Entity ID
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                # TODO: The PORT number for this port and the UNI port are the same. Correct?
                port_num=self._pon_port_num,                            # Port ID
                tp_type=3,                                              # TP Type (IEEE 802.1p mapper service)
                tp_pointer=self._ieee_mapper_service_profile_entity_id +
                           uni_port.mac_bridge_port_num                 # TP ID, 8021p mapper ID
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-port-config-data-part-1')

            #############################################################
            # VLAN Tagging Filter config
            #
            #  EntityID will be referenced by:
            #            - Nothing
            #  References:
            #            - MacBridgePortConfigurationData for the ANI/PON side
            #
            # Set anything, this request will not be used when using Extended Vlan

            frame = VlanTaggingFilterDataFrame(
                self._mac_bridge_port_ani_entity_id,  # Entity ID
                vlan_tcis=[self._vlan_tcis_1],        # VLAN IDs
                forward_operation=0x00
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-vlan-tagging-filter-data')

            #############################################################
            # Create GalEthernetProfile - Once per ONU/PON interface
            #
            #  EntityID will be referenced by:
            #            - GemInterworkingTp
            #  References:
            #            - Nothing

            frame = GalEthernetProfileFrame(
                self._gal_enet_profile_entity_id,
                max_gem_payload_size=self._max_gem_payload
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-gal-ethernet-profile')

            ##################################################
            # UNI Specific                                   #
            ##################################################
            # MAC Bridge Port config
            # This configuration is for Ethernet UNI
            #
            #  EntityID will be referenced by:
            #            - Nothing
            #  References:
            #            - MAC Bridge Service Profile (the bridge)
            #            - PPTP Ethernet UNI

            frame = MacBridgePortConfigurationDataFrame(
                0x000,                                   # Entity ID - This is read-only/set-by-create !!!
                bridge_id_pointer=self._mac_bridge_service_profile_entity_id,  # Bridge Entity ID
                port_num=self._uni_port_num,             # Port ID
                tp_type=1,                               # PPTP Ethernet UNI
                tp_pointer=self._ethernet_uni_entity_id  # TP ID, 8021p mapper Id
            ).create()
            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'create-mac-bridge-port-config-data-part-2')

        except TimeoutError as _e:
            self.log.warn('rx-timeout-download', frame=hexlify(frame))
            raise

        except Exception as e:
            self.log.exception('omci-setup-1', e=e)
            raise

        returnValue(None)

    @inlineCallbacks
    def enable_uni(self, uni, force_lock):
        """
        Lock or unlock one or more UNI ports

        :param unis: (list) of UNI objects
        :param force_lock: (boolean) If True, force lock regardless of enabled state
        """
        omci_cc = self._onu_device.omci_cc

        ##################################################################
        #  Lock/Unlock UNI  -  0 to Unlock, 1 to lock
        #
        #  EntityID is referenced by:
        #            - MAC bridge port configuration data for the UNI side
        #  References:
        #            - Nothing
        try:
            state = 1 if force_lock or not uni.enabled else 0

            frame = PptpEthernetUniFrame(uni.entity_id,
                                         attributes=dict(administrative_state=state)).set()

            results = yield omci_cc.send(frame)
            self.check_status_and_state(results, 'set-pptp-ethernet-uni-lock-restore')

        except TimeoutError:
            self.log.warn('rx-timeout-uni-enable', uni_port=uni)
            raise

        except Exception as e:
            self.log.exception('omci-failure', e=e)
            raise

        returnValue(None)
