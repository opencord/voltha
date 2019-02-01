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

from voltha.adapters.adtran_olt.codec.ietf_interfaces import (
    IetfInterfacesConfig, IetfInterfacesState
)
from mock import MagicMock
from pytest_twisted import inlineCallbacks
from xmltodict import parse


def test_create_config():
    IetfInterfacesConfig(None)


@inlineCallbacks
def test_get_config():
    session = MagicMock()
    ifc = IetfInterfacesConfig(session)
    session.get.return_value = 'test value'
    cfg = yield ifc.get_config()
    assert 'test value' == cfg
    assert ('running',) == session.get.call_args[0]
    xml = parse(session.get.call_args[1]['filter'])
    contents = {
        'filter': {
            '@xmlns': 'urn:ietf:params:xml:ns:netconf:base:1.0',
            'interfaces': {
                '@xmlns': 'urn:ietf:params:xml:ns:yang:ietf-interfaces',
                'interface': None
            }
        }
    }
    assert contents == xml


def test_create_state():
    IetfInterfacesState(None)


@inlineCallbacks
def test_get_state():
    session = MagicMock()
    ifc = IetfInterfacesState(session)
    session.get.return_value = 'test value'
    state = yield ifc.get_state()
    assert 'test value' == state
    xml = parse(session.get.call_args[0][0])
    contents = {
        'filter': {
            '@xmlns': 'urn:ietf:params:xml:ns:netconf:base:1.0',
            'interfaces-state': {
                '@xmlns': 'urn:ietf:params:xml:ns:yang:ietf-interfaces',
                'interface': {
                    'name': None,
                    'type': None,
                    'admin-status': None,
                    'oper-status': None,
                    'last-change': None,
                    'phys-address': None,
                    'speed': None
                }
            }
        }
    }
    assert contents == xml
