#
# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import structlog
from evc import EVC
from acl import ACL

import voltha.core.flow_decomposer as fd
from voltha.protos.openflow_13_pb2 import OFPP_IN_PORT, OFPP_TABLE, OFPP_NORMAL, OFPP_FLOOD, OFPP_ALL
from voltha.protos.openflow_13_pb2 import OFPP_CONTROLLER, OFPP_LOCAL, OFPP_ANY, OFPP_MAX

log = structlog.get_logger()


class FlowEntry(object):
    """
    Provide a class that wraps the flow rule and also provides state/status for
    a FlowEntry.
    """
    def __init__(self, flow, handler):
        self._flow = flow
        self._handler = handler
        log.debug('Initializing a new FlowEntry', flow=flow)

    @property
    def name(self):
        return 'Flow-{}'.format(self.flow.id)

    @property
    def flow(self):
        return self._flow

    @property
    def handler(self):
        return self._handler

    @staticmethod
    def create(flow, handler):
        """
        Create the appropriate FlowEntry wrapper for the flow

        :param flow:   (Flow) Flow entry passed to VOLTHA adapter
        :param handler: (AdtranDeviceHandler) handler for the device

        :return: (FlowEntry) A flow entry of the appropriate type
        """
        # Determine the type of flow entry. An ACL type entry is use to send
        # packets to a reserved port (controller) or to drop them.

        in_port = fd.get_in_port(flow)
        out_port = fd.get_out_port(flow)

        if in_port or out_port is None:
            return None

        # Convert all possible physical ports into a single number for matching purposes

        if in_port <= OFPP_MAX:
            in_port = OFPP_MAX

        if out_port <= OFPP_MAX:
            in_port = OFPP_MAX

        # Commented out entries below represent future desireable combinations, but not supported
        # in initial release of this device adapter.

        flow_type = {
            (OFPP_MAX, OFPP_MAX): EVCFlowEntry,         # Physical port to physical port
            (OFPP_ANY, OFPP_CONTROLLER): ACLFlowEntry,  # A common SDN/Openflow operation
            (OFPP_MAX, OFPP_TABLE): EVCFlowEntry,       # Perhaps double-tagging?
            # (OFPP_MAX, OFPP_LOCAL): ACLFlowEntry,
            # (OFPP_ANY, OFPP_LOCAL): ACLFlowEntry,
            # (OFPP_LOCAL, OFPP_MAX): ACLFlowEntry,
            # (OFPP_MAX, OFPP_IN_PORT): EVCFlowEntry,
            # (OFPP_ANY, OFPP_IN_PORT): EVCFlowEntry,

        }.get((in_port, out_port), None)

        return None if flow_type is None else flow_type(FlowEntry(flow, handler))

    ######################################################
    # Bulk operations

    @staticmethod
    def enable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def disable_all():
        raise NotImplemented("TODO: Implement this")

    @staticmethod
    def remove_all():
        """
        Remove all matching EVCs and associated EVC MAPs from hardware

        :param regex_: (String) Regular expression for name matching
        """
        raise NotImplemented("TODO: Implement this")


class EVCFlowEntry(FlowEntry):
    def __init__(self, flow, handler):
        super(FlowEntry, self).__init__(flow, handler)
        self.evc = EVC.create(flow, handler)

    @property
    def valid(self):
        return self.evc.valid

    @property
    def installed(self):
        return self.evc.installed

    def install(self):
        return self.evc.install()

    def remove(self):
        return self.evc.remove()

    def enable(self):
        return self.evc.enable()

    def disable(self):
        return self.evc.disable()


class ACLFlowEntry(FlowEntry):
    def __init__(self, flow, handler):
        super(FlowEntry, self).__init__(flow, handler)
        self.acl = ACL.create(flow, handler)

    @property
    def valid(self):
        return self.acl.valid

    @property
    def installed(self):
        return self.acl.installed

    def install(self):
        return self.acl.install()

    def remove(self):
        return self.acl.remove()

    def enable(self):
        return self.acl.enable()

    def disable(self):
        return self.evc.disable()

