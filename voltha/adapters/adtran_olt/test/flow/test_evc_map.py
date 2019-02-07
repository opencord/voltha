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


from voltha.adapters.adtran_olt.flow.evc_map import EVCMap
from mock import MagicMock
import pytest



## This section test the properties of the class EVCMap

def test_EVCMap_properties():
    flow = MagicMock()
    flow.logical_port = 100
    flow.flow_id = 200
    testmap = EVCMap(flow,300,False)
    assert testmap.valid == False
    assert testmap.installed == False
    assert testmap.name == 'VOLTHA-100-200'
    assert testmap.evc == None
    assert testmap._needs_acl_support == False
    assert testmap.pon_id == None
    assert testmap.onu_id == None
    assert testmap.gem_ids_and_vid == {}


    # TODO: needs_update property could use refactoring
    assert testmap.needs_update == False

    # setting the private _needs_update variable != falsey
    testmap._needs_update = 'update_true'
    assert testmap.needs_update == 'update_true'

    # testing that the setter only operates on Falsey arg
    testmap.needs_update = ''
    assert testmap.needs_update == False

    # testing that it does not allow Truthy things
    with pytest.raises(AssertionError):
        testmap.needs_update = 1


##  This section to test static methods of the class EVCMap

def test_create_ingress_map():
    flow = MagicMock()
    flow.logical_port = 101
    flow.flow_id = 201
    evc = MagicMock()
    dry_run = False
    emap = EVCMap.create_ingress_map(flow, evc, dry_run)
    assert isinstance(emap, EVCMap)
    evc.add_evc_map.assert_called_once_with(emap)
    assert emap.evc == evc


def test_create_egress_map():
    flow = MagicMock()
    flow.logical_port = 102
    flow.flow_id = 202
    evc = MagicMock()
    dry_run = False
    imap = EVCMap.create_egress_map(flow, evc, dry_run)
    assert isinstance(imap, EVCMap)
    evc.add_evc_map.assert_called_once_with(imap)
    assert imap.evc == evc



