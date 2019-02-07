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

from voltha.adapters.adtran_onu.pon_port import PonPort
from mock import MagicMock
import pytest

## Test class PonPort init settings  ###############
def test_PonPort_inits():
    handler = MagicMock()
    handler.device_id = 100
    portnum = 1
    testponport = PonPort(handler, portnum)

    assert testponport._enabled is False
    assert testponport._valid is True
    assert testponport._handler is handler
    assert testponport._deferred is None
    assert testponport._port is None
    assert testponport._port_number == 1
    assert testponport._entity_id is None
    assert testponport._next_entity_id == PonPort.MIN_GEM_ENTITY_ID




## Test PonPort staticmethod #########
def test_create():
    handler = MagicMock()
    handler.device_id = 200
    port_no = 2
    testcreate = PonPort.create(handler, port_no)

    assert isinstance(testcreate, PonPort)
    assert testcreate._handler is handler
    assert testcreate._port_number is port_no





## Test PonPort @property #########
def test_PonPort_properties():
    handler = MagicMock()
    handler.device_id = 300
    port_no = 3
    testprop1 = PonPort(handler, port_no)

    assert testprop1.enabled is False
    assert testprop1.port_number == 3
    assert testprop1.entity_id is None
    assert testprop1.next_gem_entity_id == PonPort.MIN_GEM_ENTITY_ID
    assert testprop1.tconts == {}
    assert testprop1.gem_ports == {}


