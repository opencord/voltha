#
# Copyright 2017 the original author or authors.
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
from hexdump import hexdump
from twisted.internet import protocol

import loxi.of14
from common.utils.message_queue import MessageQueue

log = structlog.get_logger()


class OpenFlowConnection(protocol.Protocol):

    def __init__(self, agent):
        self.agent = agent  # the protocol will call agent.enter_disconnected()
                            # and agent.enter_connected() methods to indicate
                            # when state change is necessary
        self.next_xid = 1
        self.read_buffer = None
        self.rx = MessageQueue()

    def connectionLost(self, reason):
        self.agent.enter_disconnected('connection-lost', reason)

    def connectionMade(self):
        self.agent.enter_connected()

    def dataReceived(self, data):
        log.debug('data-received', len=len(data),
                  received=hexdump(data, result='return'))

        assert len(data)  # connection close shall be handled by the protocol
        buf = self.read_buffer
        if buf:
            buf += data
        else:
            buf = data

        offset = 0
        while offset < len(buf):
            if offset + 8 > len(buf):
                break  # not enough data for the OpenFlow header

            # parse the header to get type
            _version, _type, _len, _xid = \
                loxi.of14.message.parse_header(buf[offset:])

            ofp = loxi.protocol(_version)

            if (offset + _len) > len(buf):
                break  # not enough data to cover whole message

            rawmsg = buf[offset : offset + _len]
            offset += _len

            msg = ofp.message.parse_message(rawmsg)
            if not msg:
                log.warn('could-not-parse',
                         data=hexdump(rawmsg, result='return'))
            log.debug('received-msg', module=type(msg).__module__,
                  name=type(msg).__name__, xid=msg.xid, len=len(buf))
            self.rx.put(msg)

        if offset == len(buf):
            self.read_buffer = None
        else:
            self.read_buffer = buf[offset:]
            log.debug('remaining', len=len(self.read_buffer))

    def send_raw(self, buf):
        """
        Send raw bytes on the socket
        :param buf: bytes buffer
        :return: None
        """
        assert self.connected
        log.debug('sending-raw', len=len(buf))
        self.transport.write(buf)

    def send(self, msg):
        """
        Send a message
        :param msg: An OpenFlow protocol message
        :return: None
        """
        assert self.connected

        if msg.xid is None:
            msg.xid = self._gen_xid()
        buf = msg.pack()
        log.debug('sending', module=type(msg).__module__,
                  name=type(msg).__name__, xid=msg.xid, len=len(buf))
        self.transport.write(buf)
        log.debug('data-sent', sent=hexdump(buf, result='return'))

    def recv(self, predicate):
        assert self.connected
        return self.rx.get(predicate)

    def recv_any(self):
        return self.recv(lambda _: True)

    def recv_xid(self, xid):
        return self.recv(lambda msg: msg.xid == xid)

    def recv_class(self, klass):
        return self.recv(lambda msg: isinstance(msg, klass))

    def _gen_xid(self):
        xid = self.next_xid
        self.next_xid += 1
        return xid
