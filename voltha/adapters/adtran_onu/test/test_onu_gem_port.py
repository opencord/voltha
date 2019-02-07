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

from voltha.adapters.adtran_onu.onu_gem_port import OnuGemPort
import pytest
from mock import patch, MagicMock
import pytest_twisted


GEMID = 11
ALLOCID = 21
TECHPROFILEID = 31
PONID = 41
ONUID = 51
UNIID = 61
ENTITYID = 71
ENCRYPTION = False
MULTICAST = 'multicast'
TRAFFICCLASS = 'traffic_class'
ISMOCK = 'ismock'
MOCK_HANDLER_DEVICE_ID = "mock handler's device_id"
UPSTREAM = 1
DOWNSTREAM = 2
BIDIRECTIONAL = 3
TCONTENTITYID = 500
IEEEENTITYID = 525
GALENETENTITYID = 550

GEM_DATA = {
    'gemport-id': 100,
    'encryption': 'encryption',
    'uni-id': 200,
    'direction': BIDIRECTIONAL,
    'pbit-map': '0b01010101',
    'priority-q': 300,
    'max-q-size': 400,
    'weight': 500,
    'discard-config': {'max-probability' : 'max prob', 'max-threshold' : 'max thresh', 'min-threshold' : 'min thresh'},
    'discard-policy': 'WTailDrop',
    'scheduling-policy': 'StrictPriority'
    }

GEM_DATA_BAD_UNI_ID = {
    'gemport-id': 100,
    'encryption': 'encryption',
    # 'uni-id': 200,
    'direction': BIDIRECTIONAL,
    'pbit-map': '0b01010101',
    'priority-q': 300,
    'max-q-size': 400,
    'weight': 500,
    'discard-config': {'max-probability' : 'max prob', 'max-threshold' : 'max thresh', 'min-threshold' : 'min thresh'},
    'discard-policy': 'WTailDrop',
    'scheduling-policy': 'StrictPriority'
    }


def ogp_full(mock_handler):
    ogp_obj = OnuGemPort(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID, MULTICAST, TRAFFICCLASS, ISMOCK)
    return ogp_obj


def ogp_defaults(mock_handler):
    ogp_obj = OnuGemPort(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID)
    return ogp_obj


def ogp_exception(mock_handler):
    try:
        ogp_obj = OnuGemPort(mock_handler, GEM_DATA_BAD_UNI_ID, ALLOCID, TECHPROFILEID, UNIID, ENTITYID)
    except:
        raise

    return ogp_obj


@pytest.fixture()
def ogp():
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    ogp_obj = OnuGemPort.create(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID)

    return ogp_obj


def test_onu_gem_port_init_values_missing():
    """
    verify __init__ fails when no values are specified
    """

    with pytest.raises(Exception):
        OnuGemPort()


@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
def test_onu_gem_port_init_values(patched_get_logger):
    """
    verify __init__ values are set properly
    """

    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    ogp = ogp_full(mock_handler)

    patched_get_logger.assert_called_once_with(device_id=MOCK_HANDLER_DEVICE_ID, gem_id=GEM_DATA.get('gemport-id'))
    assert ogp.gem_id == GEM_DATA.get('gemport-id')
    assert ogp._alloc_id == ALLOCID
    # assert ogp_full.tech_profile_id == TECHPROFILEID
    assert ogp.tech_profile_id is None           # TODO: code says default may change to a property
    assert ogp.encryption == GEM_DATA.get('encryption')     # uses a getter so no need to inspect internal to object
    assert ogp.multicast == MULTICAST
    assert ogp.traffic_class == TRAFFICCLASS
    assert ogp._handler == mock_handler
    assert ogp._is_mock == ISMOCK

    assert ogp._gem_data == GEM_DATA
    assert ogp._entity_id == ENTITYID
    assert ogp.entity_id == ENTITYID                                # tests getter
    assert ogp._tcont_entity_id is None
    assert ogp._interworking is False
    assert ogp.uni_id == GEM_DATA['uni-id']
    assert ogp.direction == GEM_DATA.get('direction')
    assert ogp._pbit_map == GEM_DATA.get('pbit-map')[2:]
    assert ogp.pbit_map == GEM_DATA.get('pbit-map')[2:]             # tests getter
    assert ogp.priority_q == GEM_DATA.get('priority-q')
    assert ogp._max_q_size == GEM_DATA.get('max-q-size')
    assert ogp.max_q_size == GEM_DATA.get('max-q-size')             # tests getter
    assert ogp.weight == GEM_DATA.get('weight')
    assert ogp._discard_config == GEM_DATA.get('discard-config')
    assert ogp.discard_config == GEM_DATA.get('discard-config')     # tests getter
    assert ogp._discard_policy == GEM_DATA.get('discard-policy')
    assert ogp.discard_policy == GEM_DATA.get('discard-policy')     # tests getter
    assert ogp._scheduling_policy == GEM_DATA.get('scheduling-policy')
    assert ogp.scheduling_policy == GEM_DATA.get('scheduling-policy')  # tests getter


@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
def test_onu_gem_port_create(patched_get_logger):
    """
    verify call to create().

    Equivalent to creating OnuGemPort with defaults so a 'defaults' test is not needed.
    """

    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    ogp = OnuGemPort.create(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID)

    patched_get_logger.assert_called_once_with(device_id=MOCK_HANDLER_DEVICE_ID, gem_id=GEM_DATA.get('gemport-id'))
    assert ogp.gem_id == GEM_DATA.get('gemport-id')
    assert ogp._alloc_id == ALLOCID
    # assert ogp_full.tech_profile_id == TECHPROFILEID
    assert ogp.tech_profile_id is None           # TODO: code says default may change to a property
    assert ogp.encryption == GEM_DATA.get('encryption')     # uses a getter
    assert ogp.multicast is False
    assert ogp.traffic_class is None
    assert ogp._handler == mock_handler
    assert ogp._is_mock is False

    assert ogp._gem_data == GEM_DATA
    assert ogp._entity_id == ENTITYID
    assert ogp.entity_id == ENTITYID
    assert ogp._tcont_entity_id is None
    assert ogp._interworking is False
    assert ogp.uni_id == GEM_DATA['uni-id']
    assert ogp.direction == GEM_DATA.get('direction')
    assert ogp._pbit_map == GEM_DATA.get('pbit-map')[2:]
    assert ogp.pbit_map == GEM_DATA.get('pbit-map')[2:]
    assert ogp.priority_q == GEM_DATA.get('priority-q')
    assert ogp._max_q_size == GEM_DATA.get('max-q-size')
    assert ogp.max_q_size == GEM_DATA.get('max-q-size')
    assert ogp.weight == GEM_DATA.get('weight')
    assert ogp._discard_config == GEM_DATA.get('discard-config')
    assert ogp.discard_config == GEM_DATA.get('discard-config')
    assert ogp._discard_policy == GEM_DATA.get('discard-policy')
    assert ogp.discard_policy == GEM_DATA.get('discard-policy')
    assert ogp._scheduling_policy == GEM_DATA.get('scheduling-policy')
    assert ogp.scheduling_policy == GEM_DATA.get('scheduling-policy')


@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
def test_onu_gem_port_init_values_force_exception(patched_get_logger):
    """
    verify __init__ values are set properly
    """

    _ = patched_get_logger

    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    with pytest.raises(Exception) as caught_ex:
        ogp_exception(mock_handler)

    # verify the raise
    assert caught_ex.typename == 'KeyError'
    assert caught_ex.value.message == 'uni-id'


def test_onu_gem_port_setter_exceptions_max_q_size(ogp):
    """
    verify setters (and getters) for max_q_size exceptions not covered in other tests
    """
    ogp.max_q_size = 123
    assert ogp.max_q_size == 123

    ogp.max_q_size = 'auto'
    assert ogp.max_q_size == 'auto'

    with pytest.raises(Exception) as caught_ex:
        ogp.max_q_size = 'Doh!'
    assert caught_ex.typename == 'AssertionError'

    with pytest.raises(Exception) as caught_ex:
        ogp.max_q_size = 1.23
    assert caught_ex.typename == 'AssertionError'


def test_onu_gem_port_setter_exceptions_pbit_map(ogp):
    """
    verify setter for pbit_map exceptions not covered in other tests
    """
    with pytest.raises(Exception) as caught_ex:
        ogp.pbit_map = 123
    assert caught_ex.typename == 'AssertionError'

    with pytest.raises(Exception) as caught_ex:
        ogp.pbit_map = '0b001001001'
    assert caught_ex.typename == 'AssertionError'

    with pytest.raises(Exception) as caught_ex:
        ogp.pbit_map = '0b20100101'
    assert caught_ex.typename == 'Exception'
    assert caught_ex.value.message == 'pbit_map-not-binary-string-0b20100101'


@pytest_twisted.inlineCallbacks
def test_add_to_hardware_isMock():
    """
    verify call to add hardware when isMock = True
    """
    _isMock = True

    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    ogp = OnuGemPort(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID, MULTICAST, TRAFFICCLASS,
                     _isMock)

    result = yield ogp.add_to_hardware('fake', 'fake', 'fake', 'fake')
    assert result == 'mock'


@patch('voltha.adapters.adtran_onu.onu_gem_port.GemInterworkingTpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.GemPortNetworkCtpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
@pytest_twisted.inlineCallbacks
def test_add_to_hardware(patched_get_logger, ctp_class, tp_class):
    """
    verify call to add hardware when isMock = False
    """
    ctp_class.return_value.create.return_value = 'CtpFrame Create Success!'
    tp_class.return_value.create.return_value = 'TpFrame Create Success!'

    _ = patched_get_logger

    # create mock for handler
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    # CREATE the class object to be tested, send it the mock handler
    ogp = ogp_defaults(mock_handler)

    # PREPARE to call the add_hardware method

    # prepare nested 'fields' result for omci.send
    class MockResults(object):
        def __init__(self, expected_output):
            self.fields = expected_output

    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 0,
                                    'parameter_error_attributes_mask': 1234})})

    # create mock for omci
    mock_omci = MagicMock()
    mock_omci.send.return_value = mock_send_result   # omci.send() will return the nested 'fields' structure

    # Test values before in_hardware
    assert ogp.in_hardware is False

    # make the call to add_to_hardware
    result = yield ogp.add_to_hardware(mock_omci, TCONTENTITYID, IEEEENTITYID, GALENETENTITYID)

    # Test values after in_hardware
    assert ogp.in_hardware is True

    # VERIFY Results

    assert result == mock_send_result

    assert ogp.log.debug.call_count == 3

    ogp.log.debug.assert_any_call('add-to-hardware',
                                  gem_id=GEM_DATA.get('gemport-id'),
                                  gem_entity_id=ENTITYID,
                                  tcont_entity_id=TCONTENTITYID,
                                  ieee_mapper_service_profile_entity_id=IEEEENTITYID,
                                  gal_enet_profile_entity_id=GALENETENTITYID)

    ctp_class.assert_called_once_with(ENTITYID,
                                      port_id=GEM_DATA.get('gemport-id'),
                                      tcont_id=TCONTENTITYID,
                                      direction='bi-directional',
                                      upstream_tm=0x8000)

    mock_omci.send.assert_any_call('CtpFrame Create Success!')

    # the following validates the log entry and the mock_send_result from omci.send() after GemPortNetworkCtpFrame
    ogp.log.debug.assert_any_call('create-gem-port-network-ctp', status=0, error_mask=1234)

    assert ogp._tcont_entity_id == TCONTENTITYID

    tp_class.assert_called_once_with(ENTITYID,
                                     gem_port_network_ctp_pointer=ENTITYID,
                                     interworking_option=5,
                                     service_profile_pointer=IEEEENTITYID,
                                     interworking_tp_pointer=0x0,
                                     pptp_counter=1,
                                     gal_profile_pointer=GALENETENTITYID,
                                     attributes={'gal_loopback_configuration': 0})

    mock_omci.send.assert_any_call('TpFrame Create Success!')

    # the following validates the log entry and the mock_send_result from omci.send() after GemInterworkingTpFrame
    ogp.log.debug.assert_any_call('create-gem-interworking-tp', status=0, error_mask=1234)

    assert ogp._interworking is True


@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
@pytest_twisted.inlineCallbacks
def test_add_to_hardware_exceptions_bad_tcont(patched_get_logger):
    """
    verify add hardware errors and exception

    Ctp Section - Tests call to add_to_hardware with a bad tcont_entity_id
    """

    _ = patched_get_logger

    # create mock for handler
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    # CREATE the class object to be tested, send it the mock handler
    ogp = ogp_defaults(mock_handler)

    # PREPARE to call the add_hardware method

    # prepare nested 'fields' result for omci.send
    class MockResults(object):
        def __init__(self, expected_output):
            self.fields = expected_output

    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 0,
                                                                 'parameter_error_attributes_mask': 1234})})

    # create mock for omci
    mock_omci = MagicMock()
    mock_omci.send.return_value = mock_send_result  # omci.send() will return the nested 'fields' structure

    # create problem
    ogp._tcont_entity_id = 999

    with pytest.raises(Exception) as caught_ex:
        yield ogp.add_to_hardware(mock_omci, TCONTENTITYID, IEEEENTITYID, GALENETENTITYID)

    # verify the raise
    assert caught_ex.typename == 'KeyError'
    assert caught_ex.value.message == 'GEM Port already assigned to TCONT: 999'

    # undo problem
    ogp._tcont_entity_id = None


@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
@pytest_twisted.inlineCallbacks
def test_add_to_hardware_exceptions_mcast_not_supported(patched_get_logger):
    """
    verify add hardware errors and exception cases

    CtpFrame section - assert when  MULTICAST.

    """
    _ = patched_get_logger

    # create mock for handler
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    # CREATE the class object to be tested, send it the mock handler
    ogp = ogp_defaults(mock_handler)

    # PREPARE to call the add_hardware method

    # prepare nested 'fields' result for omci.send
    class MockResults(object):
        def __init__(self, expected_output):
            self.fields = expected_output

    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 0,
                                                                 'parameter_error_attributes_mask': 1234})})

    # create mock for omci
    mock_omci = MagicMock()
    mock_omci.send.return_value = mock_send_result  # omci.send() will return the nested 'fields' structure

    ogp.multicast = 999
    with pytest.raises(Exception) as caught_ex:
        yield ogp.add_to_hardware(mock_omci, TCONTENTITYID, IEEEENTITYID, GALENETENTITYID)

    # verify the raise
    assert caught_ex.typename == 'AssertionError'
    assert caught_ex.value.message == 'MCAST is not supported yet'

    # Do not try to validate the 'except' in the try/except because it uses 'assert' which confuses the test


@patch('voltha.adapters.adtran_onu.onu_gem_port.GemInterworkingTpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.GemPortNetworkCtpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
@pytest_twisted.inlineCallbacks
def test_add_to_hardware_exceptions_gem_port_failed_and_try_except(patched_get_logger, ctp_class, tp_class):
    """
    verify add hardware exception

    Ctp section - Tests Reason Code not equal to Success, GEM Port creation FAILED

    AND tests try/except logic of the CtpFrame section
    """
    ctp_class.return_value.create.return_value = 'CtpFrame Create Success!'
    tp_class.return_value.create.return_value = 'TpFrame Create Success!'

    _ = patched_get_logger

    # create mock for handler
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    # CREATE the class object to be tested, send it the mock handler
    ogp = ogp_defaults(mock_handler)

    # PREPARE to call the add_hardware method

    # prepare nested 'fields' result for omci.send
    class MockResults(object):
        def __init__(self, expected_output):
            self.fields = expected_output

    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 0,
                                                                 'parameter_error_attributes_mask': 1234})})

    # create mock for omci
    mock_omci = MagicMock()
    mock_omci.send.return_value = mock_send_result  # omci.send() will return the nested 'fields' structure


    # create problem
    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 2,
                                                                 'parameter_error_attributes_mask': 1234})})
    mock_omci.send.return_value = mock_send_result

    with pytest.raises(Exception) as caught_ex:
        yield ogp.add_to_hardware(mock_omci, TCONTENTITYID, IEEEENTITYID, GALENETENTITYID)

    # verify the raise
    assert caught_ex.typename == 'Exception'
    assert caught_ex.value.message == 'GEM Port create failed with status: 2'

    # TODO - add more error and exception tests starting a onu_gem_port line 208 (if not self._interworking:)


@pytest_twisted.inlineCallbacks
def test_remove_from_hardware_isMock():
    """
    verify call to remove hardware when isMock = True
    """
    _isMock = True

    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    ogp = OnuGemPort(mock_handler, GEM_DATA, ALLOCID, TECHPROFILEID, UNIID, ENTITYID, MULTICAST, TRAFFICCLASS,
                     _isMock)

    result = yield ogp.remove_from_hardware('fake')
    assert result == 'mock'


@patch('voltha.adapters.adtran_onu.onu_gem_port.GemInterworkingTpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.GemPortNetworkCtpFrame')
@patch('voltha.adapters.adtran_onu.onu_gem_port.structlog.get_logger')
@pytest_twisted.inlineCallbacks
def test_remove_from_hardware(patched_get_logger, ctp_class, tp_class):
    """
    verify call to remove hardware when isMock = False
    """

    ctp_class.return_value.delete.return_value = 'CtpFrame Delete Success!'
    tp_class.return_value.delete.return_value = 'TpFrame Delete Success!'

    _ = patched_get_logger

    # create mock for handler
    mock_handler = MagicMock()
    mock_handler.device_id = MOCK_HANDLER_DEVICE_ID

    # CREATE the class object to be tested, send it the mock handler
    ogp = ogp_defaults(mock_handler)

    # adjust some class instance attributes so remove_hardware will run
    ogp._interworking = True
    ogp._tcont_entity_id = 1  # not None

    # PREPARE to call the remove_hardware method

    # prepare nested 'fields' result for omci.send
    class MockResults(object):
        def __init__(self, expected_output):
            self.fields = expected_output

    mock_send_result = MockResults({'omci_message': MockResults({'success_code': 0})})

    # create mock for omci
    mock_omci = MagicMock()
    mock_omci.send.return_value = mock_send_result   # omci.send() will return the nested 'fields' structure

    # make the call to remove_from_hardware
    result = yield ogp.remove_from_hardware(mock_omci)

    # VERIFY Results
    assert result == mock_send_result

    assert ogp.log.debug.call_count == 3

    ogp.log.debug.assert_any_call('remove-from-hardware', gem_id=GEM_DATA.get('gemport-id'))

    ctp_class.assert_called_once_with(ENTITYID)

    mock_omci.send.assert_any_call('CtpFrame Delete Success!')

    # the following validates the log entry and the mock_send_result from omci.send() after GemPortNetworkCtpFrame
    ogp.log.debug.assert_any_call('delete-gem-port-network-ctp', status=0)

    assert ogp._tcont_entity_id is None

    tp_class.assert_called_once_with(ENTITYID)

    mock_omci.send.assert_any_call('TpFrame Delete Success!')

    # the following validates the log entry and the mock_send_result from omci.send() after GemInterworkingTpFrame
    ogp.log.debug.assert_any_call('delete-gem-interworking-tp', status=0)

    assert ogp._interworking is False
