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

import structlog
from twisted.internet.defer import inlineCallbacks, returnValue

from voltha.core.logical_device_agent import mac_str_to_tuple
from voltha.protos.common_pb2 import OperStatus, AdminState
from voltha.protos.device_pb2 import Port
from voltha.protos.logical_device_pb2 import LogicalPort
from voltha.protos.openflow_13_pb2 import OFPPF_100GB_FD, OFPPF_FIBER, OFPPS_LIVE, ofp_port

log = structlog.get_logger()


class NniPort(object):
    """
    A class similar to the 'Port' class in the VOLTHA
    
    TODO: Merge this with the Port class or cleanup where possible
          so we do not duplicate fields/properties/methods
    """

    def __init__(self, parent, **kwargs):
        # TODO: Weed out those properties supported by common 'Port' object
        assert parent
        assert 'port_no' in kwargs

        self.port = None
        self.logical_port = None
        self.parent = parent
        self.port_no = kwargs.get('port_no')

        self.startup = None
        log.info('Creating NNI Port {}'.format(self.port_no))

        # And optional parameters

        self.admin_state = kwargs.pop('admin_state', AdminState.UNKNOWN)
        self.oper_status = kwargs.pop('oper_status', OperStatus.UNKNOWN)
        self.label = kwargs.pop('label', 'NNI port {}'.format(self.port_no))
        self.name = kwargs.pop('name', 'nni-{}'.format(self.port_no))
        self.mac_address = kwargs.pop('mac_address',
                                      '08:00:{}{}:{}{}:{}{}:00'.format(random.randint(0, 9),
                                                                       random.randint(0, 9),
                                                                       random.randint(0, 9),
                                                                       random.randint(0, 9),
                                                                       random.randint(0, 9),
                                                                       random.randint(0, 9)))

        # TODO: May need to refine capabilities into current, advertised, and peer

        self.ofp_capabilities = kwargs.pop('ofp_capabilities', OFPPF_100GB_FD | OFPPF_FIBER)
        self.ofp_state = kwargs.pop('ofp_state', OFPPS_LIVE)
        self.current_speed = kwargs.pop('current_speed', OFPPF_100GB_FD)
        self.max_speed = kwargs.pop('max_speed', OFPPF_100GB_FD)
        self.device_port_no = kwargs.pop('device_port_no', self.port_no)

    def __str__(self):
        return "NniPort-{}: Admin: {}, Oper: {}, parent: {}".format(self.port_no,
                                                                    self.admin_state,
                                                                    self.oper_status,
                                                                    self.parent)

    def get_port(self):
        """
        Get the VOLTHA PORT object for this port
        :return: VOLTHA Port object
        """
        if self.port is None:
            self.port = Port(port_no=self.port_no,
                             label=self.label,
                             type=Port.ETHERNET_NNI,
                             admin_state=self.admin_state,
                             oper_status=self.oper_status)
        return self.port

    def get_logical_port(self):
        """
        Get the VOLTHA logical port for this port
        :return: VOLTHA logical port or None if not supported
        """
        if self.logical_port is None:
            openflow_port = ofp_port(port_no=self.port_no,
                                     hw_addr=mac_str_to_tuple(self.mac_address),
                                     name=self.name,
                                     config=0,
                                     state=self.ofp_state,
                                     curr=self.ofp_capabilities,
                                     advertised=self.ofp_capabilities,
                                     peer=self.ofp_capabilities,
                                     curr_speed=self.current_speed,
                                     max_speed=self.max_speed)

            self.logical_port = LogicalPort(id='nni{}'.format(self.port_no),
                                            ofp_port=openflow_port,
                                            device_id=self.parent.device_id,
                                            device_port_no=self.device_port_no,
                                            root_port=True)
        return self.logical_port

    @inlineCallbacks
    def start(self):
        """
        Start/enable this NNI
        
        :return: (deferred)
        """
        log.info('Starting NNI port {}'.format(self.port_no))

        # TODO: Start up any watchdog/polling tasks here

        yield returnValue('NNI Port start is a NOP at this time')

    def stop(self):
        log.info('Stopping NNI port {}'.format(self.port_no))
        d, self.startup = self.startup, None
        if d is not None:
            d.cancel()

        self.admin_state = AdminState.DISABLED
        self.oper_status = OperStatus.UNKNOWN

        yield returnValue('NNI Port stop may need more work')
        # TODO: How do we reflect this into VOLTHA
