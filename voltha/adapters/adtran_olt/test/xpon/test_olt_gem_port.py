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

from voltha.adapters.adtran_olt.xpon.olt_gem_port import OltGemPort
import pytest
from mock import patch, MagicMock
import mock
import json
import pytest_twisted


GEMID = 11
ALLOCID = 21
TECHPROFILEID = 31
PONID = 41
ONUID = 51
UNIID = 61
ENCRYPTION = False
MULTICAST = 'multicast'
TRAFFICCLASS = 'traffic_class'
HANDLER = 'handler'
ISMOCK = 'ismock'


@pytest.fixture()
def ogp():
    ogp_obj = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID, ENCRYPTION, MULTICAST, TRAFFICCLASS,
                         HANDLER, ISMOCK)
    return ogp_obj


@pytest.fixture()
def ogp_defaults():
    ogp_obj = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID)
    return ogp_obj


def test_olt_gem_port_init_values_missing():
    """
    verify __init__ fails when no values are specified
    """

    with pytest.raises(Exception):
        OltGemPort()


def test_olt_gem_port_init_values(ogp):
    """
    verify __init__ values are set properly
    """

    assert ogp.gem_id == GEMID
    assert ogp._alloc_id == ALLOCID
    assert ogp.uni_id == UNIID
    # assert ogp.tech_profile_id == TECHPROFILEID
    assert ogp.tech_profile_id is None           # TODO: code says default may change to a property
    assert ogp.encryption == ENCRYPTION
    assert ogp.multicast == MULTICAST
    assert ogp.traffic_class == TRAFFICCLASS
    assert ogp._handler == HANDLER
    assert ogp._is_mock == ISMOCK
    assert ogp._pon_id == PONID
    assert ogp._onu_id == ONUID


def test_olt_gem_port_init_values_default():
    """
    verify __init__ values are set properly using defaults
    """

    ogp = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID)

    assert ogp.gem_id == GEMID
    assert ogp._alloc_id == ALLOCID
    assert ogp.uni_id == UNIID
    # assert ogp.tech_profile_id == TECHPROFILEID
    assert ogp.tech_profile_id is None           # TODO: code says default may change to a property
    assert ogp.encryption is False
    assert ogp.multicast is False
    assert ogp.traffic_class is None
    assert ogp._handler is None
    assert ogp._is_mock is False
    assert ogp._pon_id == PONID
    assert ogp._onu_id == ONUID


def test_olt_gem_port_getters_and_setters(ogp):
    """
    verify simple getters and setters (pon_id, onu_id, timestamp)
    """

    # ogp.pon_id('pon id set')
    assert ogp.pon_id == PONID

    # ogp.onu_id('onu id set')
    assert ogp.onu_id == ONUID

    ogp.timestamp = 'same bat time'
    assert ogp.timestamp == 'same bat time'

# prepare arguments so fixture sets up the class with known encryption setting
# and a mock for the rest call


@patch('voltha.adapters.adtran_olt.xpon.olt_gem_port.OltGemPort.set_config', return_value='not used')
def test_olt_gem_port_encryption_getters_and_setters(mock_set_config):
    """
    verify getters and setters for encryption
    """
    _encryption = True
    mock_handler = MagicMock()
    # I'm mocking handler because set_config is called with _handler.rest_client.
    # Mocking allows the rest_client attribute to be specified with no error
    # while isolating the method being tested. _handler is in the super class.

    ogp = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID, _encryption, MULTICAST, TRAFFICCLASS,
                     mock_handler, ISMOCK)

    # Set to same value
    ogp.encryption = _encryption
    assert ogp.encryption == _encryption

    # Set to opposite value
    _encryption_opposite = not _encryption
    ogp.encryption = _encryption_opposite
    assert ogp.encryption == _encryption_opposite

    mock_set_config.assert_called_once_with(mock_handler.rest_client, 'encryption', _encryption_opposite)


@pytest_twisted.inlineCallbacks
def test_add_to_hardware_ismock():
    """
    verify call to add hardware when isMock = True
    """

    _isMock = True

    ogp = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID, ENCRYPTION, MULTICAST, TRAFFICCLASS,
                     HANDLER, _isMock)

    result = yield ogp.add_to_hardware('session')
    assert result == 'mock'


@pytest_twisted.inlineCallbacks
def test_add_to_hardware_post(ogp_defaults):
    """
    verify call to add hardware with no exception using POST
    """

    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon={}/onus/onu={}/gem-ports/gem-port'.format(PONID, ONUID)
    expected_data = {"port-id": GEMID, "alloc-id": ALLOCID, "encryption": ENCRYPTION, "omci-transport": False}
    expected_name = 'gem-port-create-{}-{}: {}/{}'.format(PONID, ONUID, GEMID, ALLOCID)

    hardware_resp = 'Warning, Warning, Danger Will Robinson'

    def evaluate_request(*args, **kwargs):
        method, uri = args
        assert method == 'POST'
        assert uri == expected_uri
        assert expected_data == json.loads(kwargs['data'])
        assert expected_name == kwargs['name']

    mock_session = MagicMock()
    mock_session.request.return_value = hardware_resp

    resp = yield ogp_defaults.add_to_hardware(mock_session)
    args, kwargs = mock_session.request.call_args

    evaluate_request(*args, **kwargs)
    assert resp == hardware_resp


@pytest_twisted.inlineCallbacks
def test_add_to_hardware_except_to_patch(ogp_defaults):
    """
    verify call to add hardware with exception using POST then switch to PATCH
    """

    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon={}/onus/onu={}/gem-ports/gem-port'.format(PONID, ONUID)
    # TODO Should uri display the gem port value? Code currently omits a value.

    expected_data = {"port-id": GEMID, "alloc-id": ALLOCID, "encryption": ENCRYPTION, "omci-transport": False}
    expected_name = 'gem-port-create-{}-{}: {}/{}'.format(PONID, ONUID, GEMID, ALLOCID)

    hardware_resp = 'Warning, Warning, Danger Will Robinson'

    def evaluate_request(*args, **kwargs):
        method, uri = args
        if method == 'POST':
            raise Exception('Force an exception for POST')
        if method == 'SPLAT':
            raise Exception('Force an exception for SPLAT')
        assert method == 'PATCH'
        assert uri == expected_uri
        assert expected_data == json.loads(kwargs['data'])
        assert expected_name == kwargs['name']
        return hardware_resp

    mock_session = MagicMock()
    mock_session.request = evaluate_request

    # test with POST which will fail the try and exception to using PATCH
    hw_resp = yield ogp_defaults.add_to_hardware(mock_session)
    assert hw_resp == hardware_resp

    # test with SPLAT which will fail the try and exception to logging and the method raising an exception

    with mock.patch("voltha.adapters.adtran_olt.xpon.olt_gem_port.log.exception") as mock_log_exception:
        with pytest.raises(Exception) as caught_ex:
            yield ogp_defaults.add_to_hardware(mock_session, 'SPLAT')

        # verify the raise
        assert 'Force an exception for SPLAT' == str(caught_ex.value)

    # Verify the args sent to the log
    args, kwargs = mock_log_exception.call_args
    msg = str(args)
    gem = str(kwargs['gem'])
    e = str(kwargs['e'])

    assert msg == "('add-2-hw',)"
    assert gem == 'GemPort: 41/51/61, alloc-id: 21, gem-id: 11'
    assert e == 'Force an exception for SPLAT'


@pytest_twisted.inlineCallbacks
def test_remove_from_hardware_ismock():
    """
    verify call to remove hardware when isMock = True
    """

    _isMock = True

    ogp = OltGemPort(GEMID, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID, ENCRYPTION, MULTICAST, TRAFFICCLASS, HANDLER,
                     _isMock)

    result = yield ogp.remove_from_hardware('session')
    assert result == 'mock'


@pytest_twisted.inlineCallbacks
def test_remove_from_hardware(ogp_defaults):
    """
    verify call to remove hardware
    """

    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon={}/onus/onu={}/gem-ports/gem-port={}'.format(PONID, ONUID, GEMID)
    expected_name = 'gem-port-delete-{}-{}: {}'.format(PONID, ONUID, GEMID)

    hardware_resp = 'Warning, Warning, Danger Will Robinson'

    def evaluate_request(*args, **kwargs):
        method, uri = args
        assert method == 'DELETE'
        assert uri == expected_uri
        assert expected_name == kwargs['name']

    mock_session = MagicMock()
    mock_session.request.return_value = hardware_resp

    resp = yield ogp_defaults.remove_from_hardware(mock_session)
    args, kwargs = mock_session.request.call_args

    evaluate_request(*args, **kwargs)
    assert resp == hardware_resp


def test_set_config(ogp_defaults):
    """
    verify call to set_config
    """

    _leaf = 'ima leaf'
    _value = 'ima value'

    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon={}/onus/onu={}/gem-ports/gem-port={}'.format(PONID, ONUID, GEMID)
    expected_data = {'ima leaf': 'ima value'}
    expected_name = 'onu-set-config-{}-{}-{}'.format(PONID, _leaf, _value)

    hardware_resp = "'alloc-id': {}, 'encryption': True, 'omci-transport': False, 'port-id': {}'".format(ALLOCID, PONID)

    def evaluate_request(*args, **kwargs):
        method, uri = args
        assert method == 'PATCH'
        assert uri == expected_uri
        assert expected_data == json.loads(kwargs['data'])
        assert expected_name == kwargs['name']
        return hardware_resp

    mock_session = MagicMock()
    mock_session.request = evaluate_request

    hw_resp = ogp_defaults.set_config(mock_session, _leaf, _value)
    assert hw_resp == hardware_resp


def test_create():
    """
    verify call to create
    """
    _gem = MagicMock()
    _gem.gemport_id = 123
    _gem.aes_encryption = "TrUe"
    _ofp_port_num = 321

    response = OltGemPort.create(HANDLER, _gem, ALLOCID, TECHPROFILEID, PONID, ONUID, UNIID, _ofp_port_num)

    assert response.gem_id == _gem.gemport_id
    assert response._alloc_id == ALLOCID
    assert response.tech_profile_id is None     # TODO: code says default may change to a property
    assert response._pon_id == PONID
    assert response._onu_id == ONUID
    assert response.uni_id == UNIID
    assert response.encryption is True
    assert response._handler == HANDLER
    assert response.multicast is False
