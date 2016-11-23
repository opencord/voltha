#
# Copyright 2016 the original author or authors.
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
Mock device adapter for testing.
"""
from uuid import uuid4

import structlog
from zope.interface import implementer

from voltha.adapters.interface import IAdapterInterface
from voltha.core.device_model import mac_str_to_tuple
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import DeviceType, DeviceTypes, Device, Port
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import INFO
from voltha.protos.logical_device_pb2 import LogicalDevice
from voltha.protos.openflow_13_pb2 import ofp_desc, ofp_port, OFPPF_1GB_FD, \
    OFPPF_FIBER, OFPPS_LIVE

log = structlog.get_logger()


@implementer(IAdapterInterface)
class SimulatedAdapter(object):

    name = 'simulated'

    def __init__(self, proxy, config):
        self.proxy = proxy
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Voltha project',
            version='0.1',
            config=AdapterConfig(log_level=INFO)
        )

    def start(self):
        log.debug('starting')
        # TODO tmp: populate some devices and logical devices
        self._tmp_populate_stuff()
        log.info('started')

    def stop(self):
        log.debug('stopping')
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=[
            DeviceType(id='simulated_olt', adapter=self.name),
            DeviceType(id='simulated_onu', adapter=self.name)
        ])

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        raise NotImplementedError()

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def deactivate_device(self, device):
        raise NotImplementedError()

    def _tmp_populate_stuff(self):
        """
        pretend that we discovered some devices and create:
        - devices
        - device ports for each
        - logical device
        - logical device ports
        """

        olt = Device(
            id='simulated_olt_1',
            type='simulated_olt',
            root=True,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter=self.name
        )
        self.proxy.create_device(olt)
        for id in ['eth', 'pon']:
            port = Port(id=id)
            self.proxy.add_port(olt.id, port)

        onu1 = Device(
            id='simulated_onu_1',
            type='simulated_onu',
            root=False,
            parent_id=olt.id,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter=self.name
        )
        self.proxy.create_device(onu1)
        for id in ['eth', 'pon']:
            port = Port(id=id)
            self.proxy.add_port(onu1.id, port)

        onu2 = Device(
            id='simulated_onu_2',
            type='simulated_onu',
            root=False,
            parent_id=olt.id,
            vendor='simulated',
            model='n/a',
            hardware_version='n/a',
            firmware_version='n/a',
            software_version='1.0',
            serial_number=uuid4().hex,
            adapter=self.name
        )
        self.proxy.create_device(onu2)
        for id in ['eth', 'pon']:
            port = Port(id=id)
            self.proxy.add_port(onu2.id, port)

        ld = LogicalDevice(
            id='simulated1',
            datapath_id=1,
            desc=ofp_desc(
                mfr_desc='cord porject',
                hw_desc='simualted pon',
                sw_desc='simualted pon',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            )
        )
        self.proxy.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        for port_no, name in [(1, 'onu1'), (2, 'onu2'), (129, 'olt1')]:
            port = ofp_port(
                port_no=port_no,
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % port_no),
                name=name,
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            )
            self.proxy.add_logical_port(ld.id, port)

