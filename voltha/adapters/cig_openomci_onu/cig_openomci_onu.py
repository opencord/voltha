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
CIG OpenOMCI OLT/ONU adapter.

This adapter does NOT support XPON
"""

from twisted.internet import reactor, task
from zope.interface import implementer

from voltha.adapters.brcm_openomci_onu.brcm_openomci_onu import BrcmOpenomciOnuAdapter
from voltha.adapters.brcm_openomci_onu.brcm_openomci_onu_handler import BrcmOpenomciOnuHandler
from voltha.adapters.interface import IAdapterInterface
from voltha.protos import third_party
from voltha.protos.adapter_pb2 import Adapter
from voltha.protos.adapter_pb2 import AdapterConfig
from voltha.protos.common_pb2 import LogLevel
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Port, Image
from voltha.protos.health_pb2 import HealthStatus

from common.frameio.frameio import hexify
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from voltha.adapters.brcm_openomci_onu.omci.brcm_capabilities_task import BrcmCapabilitiesTask
from voltha.adapters.brcm_openomci_onu.omci.brcm_get_mds_task import BrcmGetMdsTask
from voltha.adapters.brcm_openomci_onu.omci.brcm_mib_sync import BrcmMibSynchronizer
from copy import deepcopy


_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class CigOpenomciOnuAdapter(BrcmOpenomciOnuAdapter):

    name = 'cig_openomci_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            #vendor_ids=[],
            vendor_ids=['CIGG'],
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        super(CigOpenomciOnuAdapter, self).__init__(adapter_agent, config)
        # self.adapter_agent = adapter_agent
        # self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='CIG Tech',
            version='0.10',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        # self.devices_handlers = dict()

        # Customize OpenOMCI for CIG ONUs
        self._omci_support_cls = deepcopy(OpenOmciAgentDefaults)

        # self.broadcom_omci['mib-synchronizer']['state-machine'] = BrcmMibSynchronizer
        # self.broadcom_omci['mib-synchronizer']['database'] = MibDbVolatileDict
        # self.broadcom_omci['omci-capabilities']['tasks']['get-capabilities'] = BrcmCapabilitiesTask

        # self._omci_agent = OpenOMCIAgent(self.adapter_agent.core,
        #                                  support_classes=self.broadcom_omci)

        self._omci_agent = OpenOMCIAgent(self.adapter_agent.core, support_classes=self._omci_support_cls)
        # register for adapter messages
        # self.adapter_agent.register_for_inter_adapter_messages()

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)
        
    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def __download_image_success(self, image_download):
        log.debug("__download_image_success")

    def __download_image_fail(self, fail):
        log.debug("__download_image_fail", failure=fail)
        
    # TODO: Add callback to the defer to indicate download status
    def download_image(self, device, request):
        log.debug('download_image', device=device, request=request)
        onu_dev = self._omci_agent.get_device(device.id)
        d = onu_dev.do_onu_software_download(request)
        d.addCallbacks(self.__download_image_success, self.__download_image_fail)
        # return d
 
    def get_image_download_status(self, device, request):
        log.debug('get_image_download_status', device=device, request=request)
        onu_dev = self._omci_agent.get_device(device.id)
        return onu_dev.get_image_download_status(request.name) if onu_dev else None
        
    def cancel_image_download(self, device, request):
        log.debug('cancel_image_download', device=device, request=request)
        onu_dev = self._omci_agent.get_device(device.id)
        onu_dev.cancel_onu_software_download(request.name)
        
    def activate_image_update(self, device, request):
        log.debug('activate_image_update', device=device, request=request)
        onu_dev = self._omci_agent.get_device(device.id)
        d = onu_dev.do_onu_image_activate(request.name)

    def revert_image_update(self, device, request):
        log.debug('revert_image_update', device=device, request=request)


