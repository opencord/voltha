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

from voltha.adapters.adtran_olt.xpon.best_effort import BestEffort
from mock import patch, MagicMock
import pytest

# Globals
# consider parametrizing these attributes
bw = 100000000000
pr = 127
wt = 100

pon_id = 0
onu_id = 1
alloc_id = 1024


def test_best_effort_init_values_missing():
    """
    verify __init__ fails when no values are specified
    """

    with pytest.raises(Exception):
        obj = BestEffort()


@pytest.fixture(scope="module")
def be():
    be_obj = BestEffort(bw, pr, wt)
    return be_obj


def test_best_effort_init_values(be):
    """
    verify __init__ values are set properly
    """

    assert bw == be.bandwidth
    assert pr == be.priority
    assert wt == be.weight


def test_best_effort_str_values(be):
    """
    verify __str__ values are set properly
    """

    expected_str_value = "BestEffort: {}/p-{}/w-{}".format(bw, pr, wt)
    actual_str_val = str(be)

    assert expected_str_value == actual_str_val


def test_best_effort_dict_values(be):
    """
    verify dict values are set properly
    """

    expected_dict = {
            'bandwidth': bw,
            'priority': pr,
            'weight': wt
        }

    actual_dict = be.to_dict()

    assert expected_dict == actual_dict


def test_add_to_hardware_with_internal_calls(be):
    """
    verify calls to add hardware. Uses internal calls
    """
    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon=0/onus/onu=1/t-conts/t-cont=1024'
    expected_data = {"best-effort": {"priority": pr, "bandwidth": bw, "weight": wt}}
    expected_name = 'tcont-best-effort-{}-{}: {}'.format(pon_id, onu_id, alloc_id)
    hardware_resp = 'Warning, Warning, Danger Will Robinson'

    def evaluate_request(*args, **kwargs):
        method, uri = args
        assert method == 'PATCH'
        assert uri == expected_uri
        assert expected_data == eval(kwargs['data'])
        assert expected_name == kwargs['name']
        return hardware_resp

    mock_session = MagicMock()
    mock_session.request = evaluate_request
    resp = be.add_to_hardware(mock_session, pon_id, onu_id, alloc_id, be)
    assert resp == hardware_resp


@patch('voltha.adapters.adtran_olt.xpon.best_effort.json.dumps', return_value='mocked_data')
def test_add_to_hardware_isolated(mock_json_dumps, be):
    """
    verify calls to add hardware. Internal call to json.dumps is mocked
    """

    mock_best_effort = MagicMock()
    mock_session = MagicMock()

    mock_best_effort.to_dict.return_value = 'empty dictionary'

    be.add_to_hardware(mock_session, pon_id, onu_id, alloc_id, mock_best_effort)

    expected_uri = '/restconf/data/gpon-olt-hw:olt/pon=0/onus/onu=1/t-conts/t-cont=1024'
    expected_data = 'mocked_data'
    expected_name = 'tcont-best-effort-0-1: 1024'

    mock_json_dumps.assert_called_once_with({'best-effort': 'empty dictionary'})

    mock_session.request.assert_called_once_with('PATCH', expected_uri, data=expected_data, name=expected_name)
