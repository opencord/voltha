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

import random

# import structlog
# import xmltodict
# from port import OpenOltPrt
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue, succeed, fail
from twisted.python.failure import Failure
from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port


class NniPort(object):
    """
    Northbound network port, often Ethernet-based

    This is a highly reduced version taken from the adtran nni_port code set
    TODO:   add functions to allow for port specific values and operations

    """
    def __init__(self, **kwargs):
        # super(NniPort, self).__init__( **kwargs)

        # TODO: Extend for use in the openolt adapter set.


        self.port_no = kwargs.get('port_no')
        self._port_no = self.port_no
        self._name = kwargs.get('name', 'nni-{}'.format(self._port_no))

        self._logical_port = None


        # Statistics
        self.intf_id = kwargs.pop('intf_id', None)
        self.port_no = 0
        self.rx_bytes = 0
        self.rx_packets = 0
        self.rx_mcast_packets = 0
        self.rx_bcast_packets = 0

        self.rx_error_packets = 0
        self.tx_bytes = 0
        self.tx_packets = 0
        self.tx_ucast_packets = 0
        self.tx_mcast_packets = 0
        self.tx_bcast_packets = 0
        self.tx_error_packets = 0
        return

    def __str__(self):
        return "NniPort-{}: Admin: {}, Oper: {}, parent: {}".format(self._port_no,
                                                                    self._admin_state,
                                                                    self._oper_status,
                                                                    self._parent)





