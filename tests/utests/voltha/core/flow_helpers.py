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

