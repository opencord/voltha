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
Asfvolt16 OLT adapter
"""

from uuid import uuid4
import structlog
import grpc
from grpc._channel import _Rendezvous
from twisted.internet.defer import inlineCallbacks

from voltha.registry import registry
from voltha.protos.common_pb2 import OperStatus, ConnectStatus
from voltha.protos.device_pb2 import Port
from voltha.protos.common_pb2 import AdminState
from voltha.protos.logical_device_pb2 import LogicalPort, LogicalDevice
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_FIBER, \
    OFPPF_1GB_FD, OFPC_GROUP_STATS, OFPC_PORT_STATS, OFPC_TABLE_STATS, \
    OFPC_FLOW_STATS, ofp_switch_features, ofp_desc, ofp_port
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.adapters.asfvolt16_olt.protos import bal_pb2

class Asfvolt16Handler(object):
    def __init__(self, adapter, device_id):
        self.adapter = adapter
        self.adapter_agent = adapter.adapter_agent
        self.device_id = device_id
        self.log = structlog.get_logger(device_id=device_id)
        self.io_port = None
        self.logical_device_id = None
        self.nni_port = None
        self.ofp_port_no = None
        self.interface = registry('main').get_args().interface
        self.pm_metrics = None
        self.alarms = None
        self.grpc_client = GrpcClient(self.log)

    def __del__(self):
        if self.io_port is not None:
            registry('frameio').close_port(self.io_port)

    def get_channel(self):
        return self.grpc_client.channel

    def send_set_remote(self):
        pass

    @inlineCallbacks
    def send_connect_olt(self):
        self.log.info('Initializing BAL')
        channel = self.get_channel()
        self.stub = bal_pb2.BalStub(channel)
        init = bal_pb2.BalInit()
        # TODO: Remove hard-coded BAL mgmt ip and port
        init.balapi_mgmt_ip_port = "192.168.24.20"
        init.core_mgmt_ip_port = "24497"
        yield self.stub.BalApiInit(init)
        self.log.info('Initialized BAL')

    def send_activate_olt(self):
        pass

    def activate(self, device):
        self.log.info('activating olt', device=device)

        if self.logical_device_id is not None:
            return

        if not device.host_and_port:
            device.oper_status = OperStatus.FAILED
            device.reason = 'No host_and_port field provided'
            self.adapter_agent.update_device(device)
            return

        self.log.info('starting grpc client')
        self.grpc_client.connect(device.host_and_port)
        self.log.info('started grpc client')

        device.root = True
        device.vendor = 'Edgecore'
        device.model = 'ASFvOLT16'
        device.serial_number = device.ipv4_address
        self.adapter_agent.update_device(device)

        nni_port = Port(
            port_no=1,
            label='NNI facing Ethernet port',
            type=Port.ETHERNET_NNI,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        )
        self.adapter_agent.add_port(self.device_id, nni_port)
        self.adapter_agent.add_port(self.device_id, Port(
            port_no=100,
            label='PON port',
            type=Port.PON_OLT,
            admin_state=AdminState.ENABLED,
            oper_status=OperStatus.ACTIVE
        ))

        ld = LogicalDevice(
            # not setting id and datapth_id will let the adapter
            # agent pick id
            desc=ofp_desc(
                mfr_desc='cord project',
                hw_desc='n/a',
                sw_desc='logical device for Edgecore ASFvOLT16 OLT',
                serial_num=uuid4().hex,
                dp_desc='n/a'
            ),
            switch_features=ofp_switch_features(
                n_buffers=256,  # TODO fake for now
                n_tables=2,  # TODO ditto
                capabilities=(  # TODO and ditto
                    OFPC_FLOW_STATS
                    | OFPC_TABLE_STATS
                    | OFPC_PORT_STATS
                    | OFPC_GROUP_STATS
                )
            ),
            root_device_id=self.device_id
        )
        ld_initialized = self.adapter_agent.create_logical_device(ld)
        cap = OFPPF_1GB_FD | OFPPF_FIBER
        self.adapter_agent.add_logical_port(ld_initialized.id, LogicalPort(
            id='nni',
            ofp_port=ofp_port(
                port_no=0,  # is 0 OK?
                hw_addr=mac_str_to_tuple('00:00:00:00:00:%02x' % 129),
                name='nni',
                config=0,
                state=OFPPS_LIVE,
                curr=cap,
                advertised=cap,
                peer=cap,
                curr_speed=OFPPF_1GB_FD,
                max_speed=OFPPF_1GB_FD
            ),
            device_id=self.device_id,
            device_port_no=nni_port.port_no,
            root_port=True
        ))

        self.send_set_remote()
        self.send_connect_olt()
        self.send_activate_olt()

        device = self.adapter_agent.get_device(device.id)
        device.root = True
        device.vendor = 'Edgecore'
        device.model = 'ASFvOLT16'
        device.serial_number = device.host_and_port
        device.parent_id = ld_initialized.id
        device.connect_status = ConnectStatus.REACHABLE
        device.oper_status = OperStatus.ACTIVE
        self.adapter_agent.update_device(device)
        self.logical_device_id = ld_initialized.id
        self.adapter_agent.update_device(device)

class GrpcClient(object):
    def __init__(self, log):
        self.channel = None
        self.connected = False
        self.log = log

    def connect(self, endpoint):
        if self.connected:
            return
        try:
            self.log.info('insecurely connecting', endpoint=endpoint)
            self.channel = grpc.insecure_channel(endpoint)
            self.connected = True
            self.log.info('insecurely connected', endpoint=endpoint)
            return

        except _Rendezvous, e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                self.log.info('grpc-endpoint-not-available')
            else:
                self.log.exception(e)

        except Exception, e:
            self.log.exception('cannot-connect', endpoint=endpoint)
