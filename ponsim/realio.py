#
# Copyright 2016 the original author or authors.
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
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from twisted.internet.defer import inlineCallbacks, returnValue

from common.frameio.frameio import FrameIOManager, hexify

log = structlog.get_logger()


class RealIo(object):

    def __init__(self, iface_map):
        self.port_to_iface_name = iface_map
        self.iface_name_to_port = dict((n, p) for p, n in iface_map.items())
        self.frame_io = FrameIOManager()
        self.ponsim = None
        self.io_ports = dict()

    @inlineCallbacks
    def start(self):
        log.debug('starting')
        yield self.frame_io.start()
        for port, iface_name in self.port_to_iface_name.items():
            io_port = self.frame_io.open_port(iface_name, self.ingress)
            self.io_ports[port] = io_port
        log.info('started')
        returnValue(self)

    @inlineCallbacks
    def stop(self):
        log.debug('stopping')
        try:
            for port in self.io_ports.values():
                yield self.frame_io.del_interface(port.iface_name)
            yield self.frame_io.stop()
            log.info('stopped')
        except Exception, e:
            log.exception('exception', e=e)

    def register_ponsim(self, ponsim):
        self.ponsim = ponsim

    def ingress(self, io_port, frame):
        port = self.iface_name_to_port.get(io_port.iface_name)
        log.debug('ingress', port=port, iface_name=io_port.iface_name,
                  frame=hexify(frame))
        decoded_frame = Ether(frame)
        if self.ponsim is not None:
            self.ponsim.ingress(port, decoded_frame)

    def egress(self, port, frame):
        if isinstance(frame, Packet):
            frame = str(frame)
        io_port = self.io_ports[port]
        log.debug('sending', port=port, frame=hexify(frame))
        io_port.send(frame)
