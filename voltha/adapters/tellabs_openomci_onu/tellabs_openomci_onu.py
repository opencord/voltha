#
# Copyright 2017-present Tellabs, Inc.
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
Tellabs OpenOMCI OLT/ONU adapter.
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

from omci.omci_entities import onu_custom_me_entities

from voltha.extensions.omci.database.mib_db_ext import MibDbExternal

_ = third_party
log = structlog.get_logger()


@implementer(IAdapterInterface)
class TellabsOpenomciOnuAdapter(BrcmOpenomciOnuAdapter):

    name = 'tellabs_openomci_onu'

    supported_device_types = [
        DeviceType(
            id=name,
            vendor_ids=['BFWS', 'TSLS', 'IPHO', 'SHGJ'],
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        super(TellabsOpenomciOnuAdapter, self).__init__(adapter_agent, config)
        
        self.descriptor = Adapter(
            id=self.name,
            vendor='Tellabs Inc.',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        log.info('tellabs_openomci_onu.__init__', adapter=self.descriptor)

        self.broadcom_omci['mib-synchronizer']['state-machine'] = BrcmMibSynchronizer
        #self.broadcom_omci['mib-synchronizer']['database'] = MibDbVolatileDict
        self.broadcom_omci['mib-synchronizer']['database'] = MibDbExternal

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def custom_me_entities(self):
        return onu_custom_me_entities()

