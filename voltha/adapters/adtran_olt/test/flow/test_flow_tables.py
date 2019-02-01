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
from collections import namedtuple
from voltha.adapters.adtran_olt.flow.flow_entry import FlowEntry
from voltha.adapters.adtran_olt.flow.flow_tables import DeviceFlows, DownstreamFlows
Flow = namedtuple('Flow', 'id')
Handler = namedtuple('Handler', 'device_id')


def test_device_flows_init():
    DeviceFlows()


def test_storage_class():
    d = DeviceFlows()
    d._keytransform = super(type(d), d)._keytransform
    with pytest.raises(NotImplementedError):
        d.get(1)


def test_device_flows_good_access():
    d = DeviceFlows()
    a_flow_entry = FlowEntry(Flow(123), Handler('dev'))
    if 123 not in d:
        d[123] = a_flow_entry
    assert 123 in d
    assert d.get(123, None) is a_flow_entry
    assert len(d) is 1
    assert d.remove(123) is a_flow_entry
    assert d.get(123, None) is None
    d.add(a_flow_entry)
    del d[123]


def test_device_flows_add():
    d = DeviceFlows()
    a_flow_entry = FlowEntry(Flow(1), Handler('dev'))
    assert a_flow_entry is d.add(a_flow_entry)
    assert a_flow_entry is d.add(a_flow_entry)


def test_device_flows_bad_access_init():
    with pytest.raises(AssertionError):
        DeviceFlows(a=1, b=2)


def test_device_flows_bad_access_key():
    d = DeviceFlows()
    with pytest.raises(AssertionError):
        d['abc'] = 123
    with pytest.raises(KeyError):
        del d[123]


def test_device_flows_bad_access_value():
    d = DeviceFlows()
    with pytest.raises(AssertionError):
        d[123] = 'abc'


def test_downstream_flows_init():
    DownstreamFlows()


def test_downstream_flows_good_access():
    d = DownstreamFlows()
    key = 'test-sig'
    a_test_sig = d.add(key)
    if key not in d:
        d[key] = a_test_sig
    assert d.get(key, None) is a_test_sig
    assert len(d) is 1
    assert d.remove(key) is a_test_sig
    assert d.get(key, None) is None
    d.add(a_test_sig)
    del d[key]

