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
import pytest_twisted
import mock

from voltha.adapters.adtran_onu.onu_traffic_descriptor import OnuTrafficDescriptor
from voltha.adapters.adtran_onu.onu_tcont import OnuTCont
from voltha.adapters.adtran_onu.adtran_onu_handler import AdtranOnuHandler

EXAMPLE_DEVICE_ID = 0x12345678
EXAMPLE_TCONT_ENTITY_ID = 3345


@pytest.fixture()
def sched_policy():
    q_sched_policy = {
        'strictpriority': 1,
        'wrr': 2
    }
    return q_sched_policy


@pytest.fixture()
def tcont_data(sched_policy):
    tcont_data = {
        'tech-profile-id': 57,
        'uni-id': 633,
        'alloc-id': 2048,
        'q-sched-policy': sched_policy
    }
    return tcont_data


@pytest.fixture()
def onu_handler():
    handler = mock.MagicMock(spec=AdtranOnuHandler)
    handler.device_id = EXAMPLE_DEVICE_ID
    return handler


@pytest.fixture(name='tcont_fixture')
def onu_tcont(onu_handler, sched_policy, tcont_data):
    with mock.patch('voltha.adapters.adtran_onu.onu_tcont.structlog.get_logger'):
        return OnuTCont(onu_handler,
                        tcont_data['alloc-id'],
                        sched_policy,
                        tcont_data['tech-profile-id'],
                        tcont_data['uni-id'],
                        mock.MagicMock(spec=OnuTrafficDescriptor))


def test_onu_tcont_create(onu_handler, tcont_data):
    td = mock.MagicMock(spec=OnuTrafficDescriptor)
    onu_tcont = OnuTCont.create(onu_handler, tcont_data, td)
    onu_tcont._entity_id = 1234
    assert onu_tcont._handler == onu_handler
    assert onu_tcont.entity_id == 1234
    assert onu_tcont.tech_profile_id == 57
    assert onu_tcont.uni_id == 633
    assert onu_tcont.alloc_id == 2048
    assert isinstance(onu_tcont.sched_policy, dict)
    assert onu_tcont.FREE_TCONT_ALLOC_ID == 0xFFFF
    assert onu_tcont.FREE_GPON_TCONT_ALLOC_ID == 0xFF


@pytest_twisted.inlineCallbacks
def test_add_mock_onu_tcont_to_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = True
        tcont_fixture._handler.device_id = EXAMPLE_DEVICE_ID
        output = yield tcont_fixture.add_to_hardware(omci, tcont_fixture.FREE_TCONT_ALLOC_ID, tcont_fixture.alloc_id)
        assert output == "mock"


@pytest_twisted.inlineCallbacks
def test_add_onu_tcont_to_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        yield tcont_fixture.add_to_hardware(omci, EXAMPLE_TCONT_ENTITY_ID, tcont_fixture.alloc_id)
        assert tcont_fixture._free_alloc_id == tcont_fixture.alloc_id
        omci.send.assert_called_once()


@pytest_twisted.inlineCallbacks
def test_add_onu_tcont_to_hardware_default_id(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        yield tcont_fixture.add_to_hardware(omci, EXAMPLE_TCONT_ENTITY_ID)
        assert tcont_fixture._free_alloc_id == tcont_fixture.FREE_TCONT_ALLOC_ID
        omci.send.assert_called_once()


@pytest_twisted.inlineCallbacks
def test_entity_already_set_onu_tcont_to_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        output = yield tcont_fixture.add_to_hardware(omci, tcont_fixture.entity_id, tcont_fixture.alloc_id)
        assert output == "Already set"


@pytest_twisted.inlineCallbacks
def test_already_assigned_onu_tcont_to_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        tcont_fixture._entity_id = 1234
        with pytest.raises(KeyError):
            yield tcont_fixture.add_to_hardware(omci, EXAMPLE_TCONT_ENTITY_ID, tcont_fixture.alloc_id)


@pytest_twisted.inlineCallbacks
def test_add_onu_tcont_to_hardware_exception(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        tcont_fixture.alloc_id = "some bad value"
        with pytest.raises(Exception):
            yield tcont_fixture.add_to_hardware(omci, EXAMPLE_TCONT_ENTITY_ID, tcont_fixture.alloc_id)


@pytest_twisted.inlineCallbacks
def test_remove_mock_onu_tcont_from_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = True
        output = yield tcont_fixture.remove_from_hardware(omci)
        assert output == "mock"


@pytest_twisted.inlineCallbacks
def test_remove_onu_tcont_from_hardware_exception(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        omci.send.side_effect = Exception
        with pytest.raises(Exception):
            yield tcont_fixture.remove_from_hardware(omci)


@pytest_twisted.inlineCallbacks
def test_remove_onu_tcont_to_hardware(tcont_fixture):
    with mock.patch("voltha.extensions.omci.omci_cc") as omci:
        tcont_fixture._is_mock = False
        tcont_fixture._entity_id = 2048
        yield tcont_fixture.remove_from_hardware(omci)
        omci.send.assert_called_once()
