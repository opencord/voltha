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

import mock
import pytest
import pytest_twisted

from xmltodict import OrderedDict
from resources.physical_entities_state_xml import test_xml, physical_entities_output

from voltha.adapters.adtran_olt.codec.physical_entities_state import PhysicalEntitiesState


class MockRPCReply(object):
    def __init__(self, data_xml):
        self.data_xml = data_xml


expected_ordered_dict_output = [
    OrderedDict(
        [(u'name', u'temperature 0/1'),
         (u'availability', OrderedDict(
             [(u'@xmlns', u'http://www.adtran.com/ns/yang/adtran-physical-entity-availability'),
              (u'availability-status', None)]
         )),
         (u'classification', OrderedDict(
             [(u'@xmlns:adtn-phys-sens', u'http://www.adtran.com/ns/yang/adtran-physical-sensors'),
              ('#text', u'adtn-phys-sens:temperature-sensor-celsius')])),
              (u'is-field-replaceable', u'false')
         ]
    )
]


@pytest.fixture()
def mock_session():
    return mock.MagicMock()


@pytest.fixture()
def pes_object(mock_session):
    return PhysicalEntitiesState(mock_session)


@pytest_twisted.inlineCallbacks
def test_get_state(mock_session, pes_object):
    mock_session.get.return_value = "<some>xml</some>"
    output = yield pes_object.get_state()
    assert output == "<some>xml</some>"


def test_physical_entities_no_reply_data(pes_object):
    assert pes_object.physical_entities is None


def test_physical_entities(pes_object):
    pes_object._rpc_reply = MockRPCReply(test_xml)
    assert pes_object.physical_entities == OrderedDict([('a-string', 'something')])


def test_get_physical_entities_no_classification(pes_object):
    pes_object._rpc_reply = MockRPCReply(test_xml)
    assert pes_object.get_physical_entities() == OrderedDict([('a-string', 'something')])


def test_get_physical_entities_no_matching_classification(pes_object):
    pes_object._rpc_reply = MockRPCReply(test_xml)
    assert pes_object.get_physical_entities("test-classification") == []


def test_get_physical_entities(pes_object):
    pes_object._rpc_reply = MockRPCReply(physical_entities_output)
    output = pes_object.get_physical_entities("adtn-phys-sens:temperature-sensor-celsius")
    assert output == expected_ordered_dict_output


def test_get_physical_entities_with_list(pes_object):
    pes_object._rpc_reply = MockRPCReply(physical_entities_output)
    output = pes_object.get_physical_entities(["adtn-phys-sens:temperature-sensor-celsius", "another_classification"])
    assert output == expected_ordered_dict_output
