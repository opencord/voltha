# Copyright 2017-present Adtran, Inc.
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

import pytest
from mock import patch, MagicMock
from voltha.adapters.adtran_onu.uni_port import UniPort
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.openflow_13_pb2 import OFPPS_LIVE, OFPPF_10GB_FD, OFPPF_FIBER


UNI_PORT_NAME = 'uni-10240'         # String name of UNI port
UNI_PHYS_PORT_NUM = 10240           # Integer physical port number for UNI
UNI_OF_PORT_NUM = 'uni-10240'       # String OpenFlow port number for UNI (legacy XPON mode)
DEVICE_ID = 0                       # Arbitrary device ID
LOGICAL_DEVICE_ID = 100             # Arbitrary logical device ID
LOGICAL_PORT_NUM = 10240            # Arbitrary logical port number


@pytest.fixture(scope='function', name='fxt_uni_port')
def uni_port():
    with patch('voltha.adapters.adtran_onu.uni_port.structlog.get_logger'):
        handler = MagicMock()
        handler.device_id = DEVICE_ID
        handler.logical_device_id = LOGICAL_DEVICE_ID
        return UniPort(handler, UNI_PORT_NAME, UNI_PHYS_PORT_NUM, UNI_OF_PORT_NUM)


# Basic test of UniPort() object creation
def test_uni_port_init(fxt_uni_port):
    assert fxt_uni_port._name == UNI_PORT_NAME
    assert fxt_uni_port._port_number == UNI_PHYS_PORT_NUM
    assert fxt_uni_port._ofp_port_no == UNI_OF_PORT_NUM


# Test UniPort.__str__() to ensure proper return value
def test_uni_port___str__(fxt_uni_port):
    assert str(fxt_uni_port) == "UniPort: {}:{}".format(UNI_PORT_NAME, UNI_PHYS_PORT_NUM)


# Test static method constructor for UniPort()
def test_uni_port_create():
    handler = MagicMock()
    handler.device_id = DEVICE_ID
    uni_port = UniPort.create(handler, UNI_PORT_NAME, UNI_PHYS_PORT_NUM, UNI_OF_PORT_NUM)
    assert uni_port._handler == handler
    assert uni_port._name == UNI_PORT_NAME
    assert uni_port._port_number == UNI_PHYS_PORT_NUM
    assert uni_port._ofp_port_no == UNI_OF_PORT_NUM


# Test UniPort._start() for expected operation
def test_uni_port__start(fxt_uni_port):
    fxt_uni_port._cancel_deferred = MagicMock()
    fxt_uni_port._update_adapter_agent = MagicMock()
    fxt_uni_port._start()
    assert fxt_uni_port._admin_state == AdminState.ENABLED
    assert fxt_uni_port._oper_status == OperStatus.ACTIVE
    fxt_uni_port._cancel_deferred.assert_called_once_with()
    fxt_uni_port._update_adapter_agent.assert_called_once_with()


# # Test UniPort._stop() for expected operation
def test_uni_port__stop(fxt_uni_port):
    fxt_uni_port._cancel_deferred = MagicMock()
    fxt_uni_port._update_adapter_agent = MagicMock()
    fxt_uni_port._stop()
    assert fxt_uni_port._admin_state == AdminState.DISABLED
    assert fxt_uni_port._oper_status == OperStatus.UNKNOWN
    fxt_uni_port._cancel_deferred.assert_called_once_with()
    fxt_uni_port._update_adapter_agent.assert_called_once_with()


# # Test UniPort.delete() for expected operation
def test_uni_port_delete(fxt_uni_port):
    fxt_uni_port._start = MagicMock()
    fxt_uni_port._stop = MagicMock()
    fxt_uni_port.delete()
    assert fxt_uni_port._enabled is False
    assert fxt_uni_port._handler is None


# # Test UniPort._cancel_deferred() for expected operation
def test_uni_port__cancel_deferred(fxt_uni_port):
    fxt_uni_port._cancel_deferred()


# Test UniPort.name() getter property for expected operation
def test_uni_port_name_getter(fxt_uni_port):
    fxt_uni_port._name = 'uni-10256'
    assert fxt_uni_port.name == 'uni-10256'


@pytest.mark.parametrize("setting", [True, False])
# Test UniPort.enabled() getter property for expected operation
def test_uni_port_enabled_getter(fxt_uni_port, setting):
    fxt_uni_port._enabled = setting
    assert fxt_uni_port.enabled == setting


@pytest.mark.parametrize("initial, setting", [(False, True), (True, False), (False, False), (True, True)])
# Test UniPort.enabled() setter property for expected operation
def test_uni_port_enabled_setter(fxt_uni_port, initial, setting):
    fxt_uni_port._start = MagicMock()
    fxt_uni_port._stop = MagicMock()
    fxt_uni_port._enabled = initial
    fxt_uni_port.enabled = setting
    assert fxt_uni_port._enabled == setting
    if (initial is False) and (setting is True):
        fxt_uni_port._start.assert_called_once_with()
        fxt_uni_port._stop.assert_not_called()
    elif (initial is True) and (setting is False):
        fxt_uni_port._start.assert_not_called()
        fxt_uni_port._stop.assert_called_once_with()
    else:
        fxt_uni_port._start.assert_not_called()
        fxt_uni_port._stop.assert_not_called()


# Test UniPort.port_number() getter property for expected operation
def test_uni_port_port_number_getter(fxt_uni_port):
    fxt_uni_port._port_number = 10256
    assert fxt_uni_port.port_number == 10256


# Test UniPort.mac_bridge_port_num() getter property for expected operation
def test_uni_port_mac_bridge_port_num_getter(fxt_uni_port):
    fxt_uni_port._mac_bridge_port_num = 1
    assert fxt_uni_port.mac_bridge_port_num == 1


# Test UniPort.mac_bridge_port_num() setter property for expected operation
def test_uni_port_mac_bridge_port_num_setter(fxt_uni_port):
    fxt_uni_port._mac_bridge_port_num = 0
    fxt_uni_port.mac_bridge_port_num = 1
    assert fxt_uni_port._mac_bridge_port_num == 1


# Test UniPort.entity_id() getter property for expected operation
def test_uni_port_entity_id_getter(fxt_uni_port):
    fxt_uni_port._entity_id = 1
    assert fxt_uni_port.entity_id == 1


# Test UniPort.entity_id() setter property for expected operation
def test_uni_port_entity_id_setter(fxt_uni_port):
    fxt_uni_port._entity_id = None
    fxt_uni_port.entity_id = 1
    assert fxt_uni_port._entity_id == 1


# Test UniPort.entity_id() setter property for being called more than once (can only set entity_id once)
def test_uni_port_entity_id_setter_already_set(fxt_uni_port):
    fxt_uni_port._entity_id = 1
    with pytest.raises(AssertionError):
        fxt_uni_port.entity_id = 2
    assert fxt_uni_port._entity_id == 1


# Test UniPort.logical_port_number() getter property for expected operation
def test_uni_port_logical_port_number_getter(fxt_uni_port):
    fxt_uni_port._logical_port_number = 10256
    assert fxt_uni_port.logical_port_number == 10256


# Test UniPort._update_adapter_agent() for expected operation with self._port = None
def test_uni_port__update_adapter_agent_port_new(fxt_uni_port):
    fxt_uni_port._port = None
    fxt_uni_port.get_port = MagicMock()
    fxt_uni_port._update_adapter_agent()
    fxt_uni_port.get_port.assert_called_once_with()
    fxt_uni_port._handler.adapter_agent.add_port.assert_called_once_with(DEVICE_ID, fxt_uni_port.get_port.return_value)


# Test UniPort._update_adapter_agent() for expected operation with self._port != None
def test_uni_port__update_adapter_agent_port_exists(fxt_uni_port):
    fxt_uni_port._admin_state = AdminState.ENABLED
    fxt_uni_port._oper_status = OperStatus.ACTIVE
    fxt_uni_port._port = MagicMock()
    fxt_uni_port.get_port = MagicMock()
    fxt_uni_port._update_adapter_agent()
    assert fxt_uni_port._port.admin_state == AdminState.ENABLED
    assert fxt_uni_port._port.oper_status == OperStatus.ACTIVE
    fxt_uni_port.get_port.assert_called_once_with()
    fxt_uni_port._handler.adapter_agent.add_port.assert_called_once_with(DEVICE_ID, fxt_uni_port.get_port.return_value)


# Test UniPort._update_adapter_agent() for failed operation due to KeyError exception in add_port() call
def test_uni_port__update_adapter_agent_port_add_key_excep(fxt_uni_port):
    fxt_uni_port._port = None
    fxt_uni_port.get_port = MagicMock()
    fxt_uni_port._handler.adapter_agent.add_port.side_effect = KeyError()
    fxt_uni_port._update_adapter_agent()
    fxt_uni_port.get_port.assert_called_once_with()
    fxt_uni_port._handler.adapter_agent.add_port.assert_called_once_with(DEVICE_ID, fxt_uni_port.get_port.return_value)


# Test UniPort._update_adapter_agent() for failed operation due to any other exception in add_port() call
def test_uni_port__update_adapter_agent_port_add_other_excep(fxt_uni_port):
    fxt_uni_port._port = None
    fxt_uni_port.get_port = MagicMock()
    fxt_uni_port._handler.adapter_agent.add_port.side_effect = AssertionError()
    fxt_uni_port._update_adapter_agent()
    fxt_uni_port.get_port.assert_called_once_with()
    fxt_uni_port._handler.adapter_agent.add_port.assert_called_once_with(DEVICE_ID, fxt_uni_port.get_port.return_value)
    fxt_uni_port.log.exception.assert_called_once()


# Test UniPort.get_port() for expected operation with self._port = None
def test_uni_port_get_port(fxt_uni_port):
    with patch('voltha.adapters.adtran_onu.uni_port.Port', autospec=True) as mk_port:
        fxt_uni_port._port = None
        fxt_uni_port.port_id_name = MagicMock()
        fxt_uni_port._admin_state = AdminState.ENABLED
        fxt_uni_port._oper_status = OperStatus.ACTIVE
        mk_port.ETHERNET_UNI = Port.ETHERNET_UNI
        assert fxt_uni_port.get_port() == mk_port.return_value
        mk_port.assert_called_once_with(port_no=UNI_PHYS_PORT_NUM, label=fxt_uni_port.port_id_name.return_value,
                                        type=Port.ETHERNET_UNI, admin_state=AdminState.ENABLED,
                                        oper_status=OperStatus.ACTIVE)


# Test UniPort.port_id_name() getter property for expected operation
def test_uni_port_port_id_name(fxt_uni_port):
    fxt_uni_port._port_number = 10256
    assert fxt_uni_port.port_id_name() == 'uni-10256'


@pytest.mark.parametrize("log_port_num, multi_uni_naming, ofp_port_name", [(None, False, 'ADTN12345678'),
                                                                           (LOGICAL_PORT_NUM, True, 'ADTN12345678-1')])
# Test UniPort.add_logical_port() for expected operation with various parametrized variables
def test_uni_port_add_logical_port(fxt_uni_port, log_port_num, multi_uni_naming, ofp_port_name):
    with patch('voltha.adapters.adtran_onu.uni_port.ofp_port', autospec=True) as mk_ofp_port, \
            patch('voltha.adapters.adtran_onu.uni_port.LogicalPort', autospec=True) as mk_LogicalPort:
        fxt_uni_port._logical_port_number = log_port_num
        fxt_uni_port._handler.adapter_agent.get_logical_port.return_value = None
        device = fxt_uni_port._handler.adapter_agent.get_device.return_value
        device.parent_port_no = 1
        device.serial_number = 'ADTN12345678'
        device.id = 0
        fxt_uni_port._mac_bridge_port_num = 1
        fxt_uni_port.port_id_name = MagicMock()
        fxt_uni_port.port_id_name.return_value = 'uni-{}'.format(UNI_PHYS_PORT_NUM)
        fxt_uni_port.add_logical_port(LOGICAL_PORT_NUM, multi_uni_naming)
        assert fxt_uni_port._logical_port_number == LOGICAL_PORT_NUM
        fxt_uni_port._handler.adapter_agent.get_device.assert_called_once_with(DEVICE_ID)
        mk_ofp_port.assert_called_once_with(port_no=LOGICAL_PORT_NUM, hw_addr=(8, 0, 0, 1, 40, 0), config=0,
                                            state=OFPPS_LIVE, curr=(OFPPF_10GB_FD | OFPPF_FIBER), name=ofp_port_name,
                                            curr_speed=OFPPF_10GB_FD, advertised=(OFPPF_10GB_FD | OFPPF_FIBER),
                                            max_speed=OFPPF_10GB_FD, peer=(OFPPF_10GB_FD | OFPPF_FIBER))
        mk_LogicalPort.assert_called_once_with(id='uni-{}'.format(UNI_PHYS_PORT_NUM), ofp_port=mk_ofp_port.return_value,
                                               device_id=device.id, device_port_no=UNI_PHYS_PORT_NUM)
        fxt_uni_port._handler.adapter_agent.add_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID,
                                                                                     mk_LogicalPort.return_value)
        if log_port_num is not None:
            fxt_uni_port._handler.adapter_agent.get_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID,
                                                                                         'uni-{}'.format(UNI_PHYS_PORT_NUM))
            fxt_uni_port._handler.adapter_agent.delete_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID, None)


# Test UniPort.add_logical_port() for exception in call to delete_logical_port() method
def test_uni_port_add_logical_port_exception(fxt_uni_port):
    with patch('voltha.adapters.adtran_onu.uni_port.ofp_port', autospec=True) as mk_ofp_port, \
            patch('voltha.adapters.adtran_onu.uni_port.LogicalPort', autospec=True) as mk_LogicalPort:
        fxt_uni_port._logical_port_number = LOGICAL_PORT_NUM
        fxt_uni_port._handler.adapter_agent.get_logical_port.return_value = None
        device = fxt_uni_port._handler.adapter_agent.get_device.return_value
        device.parent_port_no = 1
        device.serial_number = 'ADTN12345678'
        device.id = 0
        fxt_uni_port._mac_bridge_port_num = 1
        fxt_uni_port.port_id_name = MagicMock()
        fxt_uni_port.port_id_name.return_value = 'uni-{}'.format(UNI_PHYS_PORT_NUM)
        # Creating an exception, but there is nothing to check for because the `except` statement only does a `pass`
        fxt_uni_port._handler.adapter_agent.delete_logical_port.side_effect = AssertionError()
        fxt_uni_port.add_logical_port(LOGICAL_PORT_NUM, False)
        assert fxt_uni_port._logical_port_number == LOGICAL_PORT_NUM
        fxt_uni_port._handler.adapter_agent.get_device.assert_called_once_with(DEVICE_ID)
        mk_ofp_port.assert_called_once_with(port_no=LOGICAL_PORT_NUM, hw_addr=(8, 0, 0, 1, 40, 0), config=0,
                                            state=OFPPS_LIVE, curr=(OFPPF_10GB_FD | OFPPF_FIBER), name='ADTN12345678',
                                            curr_speed=OFPPF_10GB_FD, advertised=(OFPPF_10GB_FD | OFPPF_FIBER),
                                            max_speed=OFPPF_10GB_FD, peer=(OFPPF_10GB_FD | OFPPF_FIBER))
        mk_LogicalPort.assert_called_once_with(id='uni-{}'.format(UNI_PHYS_PORT_NUM), ofp_port=mk_ofp_port.return_value,
                                               device_id=device.id, device_port_no=UNI_PHYS_PORT_NUM)
        fxt_uni_port._handler.adapter_agent.add_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID,
                                                                                     mk_LogicalPort.return_value)
        fxt_uni_port._handler.adapter_agent.get_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID,
                                                                                     'uni-{}'.format(UNI_PHYS_PORT_NUM))
        fxt_uni_port._handler.adapter_agent.delete_logical_port.assert_called_once_with(LOGICAL_DEVICE_ID, None)
