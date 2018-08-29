# Copyright 2017-present Open Networking Foundation
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
"""
Mixin class to help in flow inspection
"""
from unittest import TestCase

from google.protobuf.json_format import MessageToDict
from jsonpatch import make_patch
from simplejson import dumps


class FlowHelpers(TestCase):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~ HELPER METHODS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def assertFlowsEqual(self, flow1, flow2):
        if flow1 != flow2:
            self.fail('flow1 %s differs from flow2; differences: \n%s' % (
                      dumps(MessageToDict(flow1), indent=4),
                      self.diffMsgs(flow1, flow2)))

    def diffMsgs(self, msg1, msg2):
        msg1_dict = MessageToDict(msg1)
        msg2_dict = MessageToDict(msg2)
        diff = make_patch(msg1_dict, msg2_dict)
        return dumps(diff.patch, indent=2)

    def assertFlowNotInFlows(self, flow, flows):
        if flow in flows.items:
            self.fail('flow id %d is in flows' % flow.id)

    def assertFlowInFlows(self, flow, flows):
        if flow not in flows.items:
            self.fail('flow id %d is not in flows' % flow.id)
