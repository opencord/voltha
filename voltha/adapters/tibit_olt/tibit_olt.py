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
Tibit OLT device adapter
"""
import scapy
import structlog
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether
from twisted.internet.defer import DeferredQueue, inlineCallbacks
from twisted.internet import reactor

from zope.interface import implementer

from common.frameio.frameio import BpfProgramFilter
from voltha.registry import registry
from voltha.adapters.interface import IAdapterInterface
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig
from voltha.protos.device_pb2 import DeviceType, DeviceTypes
from voltha.protos.health_pb2 import HealthStatus
from voltha.protos.common_pb2 import LogLevel, ConnectStatus

from scapy.packet import Packet, bind_layers
from scapy.fields import StrField

log = structlog.get_logger()


is_tibit_frame = BpfProgramFilter('ether[12:2] = 0x9001')

# To be removed
class TBJSON(Packet):
    """ TBJSON 'packet' layer. """
    name = "TBJSON"
    fields_desc = [StrField("data", default="")]

@implementer(IAdapterInterface)
class TibitOltAdapter(object):

    name = 'tibit_olt'

    supported_device_types = [
        DeviceType(
            id='tibit_olt',
            adapter=name,
            accepts_bulk_flow_update=True
        )
    ]

    def __init__(self, adapter_agent, config):
        self.adapter_agent = adapter_agent
        self.config = config
        self.descriptor = Adapter(
            id=self.name,
            vendor='Tibit Communications Inc.',
            version='0.1',
            config=AdapterConfig(log_level=LogLevel.INFO)
        )
        self.interface = registry('main').get_args().interface
        self.io_port = None
        self.incoming_queues = {}  # mac_address -> DeferredQueue()

    def start(self):
        log.debug('starting', interface=self.interface)
        log.info('started', interface=self.interface)

    def stop(self):
        log.debug('stopping')
        if self.io_port is not None:
            registry('frameio').del_interface(self.interface)
        log.info('stopped')

    def adapter_descriptor(self):
        return self.descriptor

    def device_types(self):
        return DeviceTypes(items=self.supported_device_types)

    def health(self):
        return HealthStatus(state=HealthStatus.HealthState.HEALTHY)

    def change_master_state(self, master):
        raise NotImplementedError()

    def adopt_device(self, device):
        log.info('adopt-device', device=device)
        self._activate_io_port()
        reactor.callLater(0, self._launch_device_activation, device)
        return device

    def _activate_io_port(self):
        if self.io_port is None:
            self.io_port = registry('frameio').add_interface(
                self.interface, self._rcv_io, is_tibit_frame)

    @inlineCallbacks
    def _launch_device_activation(self, device):


        try:
            log.debug('launch_dev_activation')
            # prepare receive queue
            self.incoming_queues[device.mac_address] = DeferredQueue(size=100)

            # send out ping to OLT device
            olt_mac = device.mac_address
            ping_frame = self._make_ping_frame(mac_address=olt_mac)
            self.io_port.send(ping_frame)

            # wait till we receive a response
            # TODO add timeout mechanism so we can signal if we cannot reach device
            while True:
                response = yield self.incoming_queues[olt_mac].get()
                # verify response and if not the expected response
                if 1: # TODO check if it is really what we expect, and wait if not
                    break

        except Exception, e:
            log.exception('launch device failed', e=e)

        # if we got response, we can fill out the device info, mark the device
        # reachable
        import pdb
        pdb.set_trace()

        device.root = True
        device.vendor = 'Tibit stuff'
        device.model = 'n/a'
        device.hardware_version = 'n/a'
        device.firmware_version = 'n/a'
        device.software_version = '1.0'
        device.serial_number = 'add junk here'
        device.connect_status = ConnectStatus.REACHABLE
        self.adapter_agent.update_device(device)

    def _rcv_io(self, port, frame):

        log.info('frame-recieved')

        # extract source mac
        response = Ether(frame)

        # enqueue incoming parsed frame to rigth device
        self.incoming_queues[response.src].put(response)

    def _make_ping_frame(self, mac_address):
        # TODO Nathan to make this to be an actual OLT ping
        # Create a json packet
        json_operation_str = '{\"operation\":\"version\"}'
        frame = Ether()/TBJSON(data='json %s' % json_operation_str)
        frame.type = int("9001", 16)
        frame.dst = '00:0c:e2:31:25:00'
        bind_layers(Ether, TBJSON, type=0x9001)
        frame.show()
        return str(frame)

    def abandon_device(self, device):
        raise NotImplementedError(0
                                  )
    def deactivate_device(self, device):
        raise NotImplementedError()

    def update_flows_bulk(self, device, flows, groups):
        log.debug('bulk-flow-update', device_id=device.id,
                  flows=flows, groups=groups)

    def update_flows_incrementally(self, device, flow_changes, group_changes):
        raise NotImplementedError()

    def send_proxied_message(self, proxy_address, msg):
        log.debug('send-proxied-message',
                  proxy_address=proxy_address, msg=msg)

    def receive_proxied_message(self, proxy_address, msg):
        raise NotImplementedError()
