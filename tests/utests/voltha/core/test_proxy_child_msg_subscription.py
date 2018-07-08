# Copyright 2017-present Open Networking Foundation
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
from unittest import main, TestCase
from mock import Mock, patch
from voltha.main import Main
import voltha.core.device_agent
from voltha.core.flow_decomposer import *
from voltha.core.adapter_agent import AdapterAgent
from voltha.core.core import VolthaCore
from voltha.adapters.loader import AdapterLoader
from voltha.registry import registry, IComponent
from voltha.protos import third_party
from voltha.protos.device_pb2 import Device, Port, DeviceType
from voltha.protos.logical_device_pb2 import LogicalDevice, LogicalPort
from voltha.protos.openflow_13_pb2 import Flows, FlowGroups
from voltha.protos.common_pb2 import AdminState, LogLevel
from twisted.internet import defer


class test_proxy_child_msg_subscription(TestCase):

    def setUp(self):
        registry.register(
                          'core',
                             VolthaCore(
                              instance_id=1,
                              core_store_id=1,
                              grpc_port=50060,
                              version="1",
                              log_level=LogLevel.INFO
                             )
                          ).start()

        self.adapter_agent_ont = AdapterAgent("broadcom_onu", "BroadcomOnuAdapter")
        self.adapter_agent_olt = AdapterAgent("asfvolt16_olt", "Asfvolt16Adapter")

        # create and update the core with Broadcom ONU device type
        self.onu_device_type =  DeviceType(
                                  id='broadcom_onu',
                                  vendor_id='BRCM',
                                  adapter='broadcom_onu',
                                  accepts_bulk_flow_update=True
                                )

        # create and update the core with Broadcom ONU device type
        self.olt_device_type =  DeviceType(
                                  id='asfvolt16_olt',
                                  vendor_id='Edgecore',
                                  adapter='asfvolt16_olt',
                                  accepts_bulk_flow_update=True
                                )

        self.adapter_agent_ont._make_up_to_date('/device_types', 'broadcom_onu', self.onu_device_type)
        self.adapter_agent_olt._make_up_to_date('/device_types', 'asfvolt16_olt', self.olt_device_type)

    def tearDown(self):
        self.adapter_agent_ont._remove_node('/device_types', self.onu_device_type)
        self.adapter_agent_olt._remove_node('/device_types', self.olt_device_type)
        del self.onu_device_type
        del self.olt_device_type
        del self.adapter_agent_ont
        del self.adapter_agent_olt
        registry.unregister('core')


    # ~~~~~~~~~~~~~~~~~~~ TEST ~~~~~~~~~~~~~~~~~~~~~~

    @patch('voltha.core.device_agent.DeviceAgent._set_adapter_agent', return_value='adapter_name')
    @patch('voltha.core.device_agent.DeviceAgent._delete_device', return_value=defer.Deferred())
    def test_subsribe_to_proxy_child_messages(self, mock_set_adapter_agent, mock_delete_device):

        # Add OLT
        olt_device = Device(id='olt', root=True, parent_id='id', type='asfvolt16_olt')
        self.adapter_agent_olt.add_device(olt_device)

        # Initially when no ONUs are attached to the OLT, the tx_event_subscriptions
        # should be 0
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 0)

        # Add 1st ONU to the OLT
        onu1_proxy_address = Device.ProxyAddress(
                                      device_id='olt',
                                      channel_id=1,
                                      onu_id=1,
                                      onu_session_id=1
                                     )
        self.adapter_agent_olt.add_onu_device('olt',
                                           1,
                                          "BRCM",
                                          onu1_proxy_address,
                                          AdminState.UNKNOWN)

        # The tx_event_subscriptions should increment to 1 after adding 1st ONU
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 1)

        # Add 2nd ONU to the OLT
        onu2_proxy_address = Device.ProxyAddress(
                                      device_id='olt',
                                      channel_id=2,
                                      onu_id=2,
                                      onu_session_id=2
                                     )
        self.adapter_agent_olt.add_onu_device('olt',
                                           1,
                                          "BRCM",
                                          onu2_proxy_address,
                                          AdminState.UNKNOWN)

        # The tx_event_subscriptions should increment to 2 after adding 2nd ONU
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 2)

        # Remove one ONU
        children = self.adapter_agent_olt.get_child_devices('olt')
        self.assertEqual(len(children), 2)
        for child in children:
            self.adapter_agent_olt.delete_child_device('olt', child.id)
            break

        # The tx_event_subscriptions should decrement to 1 after removing one ONU
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 1)

        # Add new ONU to the OLT. The total ONUs on the OLT are now 2
        onu3_proxy_address = Device.ProxyAddress(
                                      device_id='olt',
                                      channel_id=3,
                                      onu_id=3,
                                      onu_session_id=3
                                     )
        self.adapter_agent_olt.add_onu_device('olt',
                                           1,
                                          "BRCM",
                                          onu3_proxy_address,
                                          AdminState.UNKNOWN)

        # The tx_event_subscriptions should increment to 2 after adding another ONU
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 2)

        # delete all child devices (ONUs)
        self.adapter_agent_olt.delete_all_child_devices('olt')

        # There should be no tx_event_subscriptions after deleting all child devices (ONUs)
        self.assertEqual(len(self.adapter_agent_olt._tx_event_subscriptions), 0)


if __name__ == '__main__':
    main()
