#!/usr/bin/env python
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
from twisted.internet.defer import inlineCallbacks, returnValue
from common.utils.message_queue import MessageQueue
from netconf.constants import Constants as C
import re

log = structlog.get_logger()

MAXSSHBUF = C.MAXSSHBUF


class NetconfConnection(protocol.Protocol):
    def __init__(self, data=None, avatar=None, max_chunk=MAXSSHBUF):
        self.avatar = avatar
        self.nc_server = self.avatar.get_nc_server()
        self.rx = MessageQueue()
        self.max_chunk = max_chunk
        self.connected = True
        self.proto_handler = None
        self.exiting = False

    def connectionLost(self, reason):
        log.info('connection-lost')
        self.connected = False
        if not self.exiting:
            self.proto_handler.stop('Connection-Lost')

    def connectionMade(self):
        log.info('connection-made')
        self.nc_server.client_connected(self)

    def dataReceived(self, data):
        log.debug('data-received', len=len(data),
                  received=hexdump(data, result='return'))
        assert len(data)
        self.rx.put(data)

    def processEnded(self, reason=None):
        log.info('process-ended', reason=reason)
        self.connected = False

    def chunkit(self, msg, maxsend):
        sz = len(msg)
        left = 0
        for unused in range(0, sz // maxsend):
            right = left + maxsend
            chunk = msg[left:right]
            left = right
            yield chunk
        msg = msg[left:]
        yield msg

    def send_msg(self, msg, new_framing):
        assert self.connected
        # Apparently ssh has a bug that requires minimum of 64 bytes?
        # This may not be sufficient to fix this.
        if new_framing:
            msg = "#{}\n{}\n##\n".format(len(msg), msg)
        else:
            msg += C.DELIMITER
        for chunk in self.chunkit(msg, self.max_chunk - 64):
            log.info('sending', chunk=chunk,
                     framing="1.1" if new_framing else "1.0")
            # out = hexdump(chunk, result='return')
            self.transport.write('{}\n'.format(chunk))

    @inlineCallbacks
    def receive_msg_any(self, new_framing):
        assert self.connected
        msg = yield self.recv(lambda _: True)
        if new_framing:
            response = yield self._receive_11(msg)
        else:
            response = yield self._receive_10(msg)
        returnValue(response)

    @inlineCallbacks
    def _receive_10(self, msg):
        # search for message end indicator
        searchfrom = 0
        partial_msgs = []
        while 1:
            eomidx = msg.find(C.DELIMITER, searchfrom)
            if eomidx != -1:
                partial_msgs.append(msg[:eomidx])
                full_msg = ''.join(partial_msgs)
                log.info('full-msg-received', msg=full_msg)
                returnValue(full_msg)
            else:
                partial_msgs.append(msg)
                log.debug('partial-msg-received', msg=msg)
                msg = yield self.recv(lambda _: True)

    @inlineCallbacks
    def _receive_11(self, msg):
        # A message can be received in chunks where each chunk is formatted as:
        # /\n#[len]\n
        # \n##\n
        # msg\n
        # msg
        # \n
        # \nmsg\n
        partial_msgs = []
        while 1:
            log.info('received-msg', msg=msg)
            # Remove all reference to length if any, i.e any '#len'
            msg = re.sub(r'#[0-9]+', "", msg)
            msg = msg.split('\n')
            if C.DELIMITER_1_1 in msg:  # The '##' is the second last ref
                partial_msgs.append(''.join(msg[0:(len(msg) - 2)]))
                full_msg = ''.join(partial_msgs)
                log.debug('full-msg-received', msg=full_msg)
                returnValue(full_msg)
            else:
                partial_msgs.append(''.join(msg))
                log.debug('partial-msg-received', msg=msg)
            msg = yield self.recv(lambda _: True)

    def close_connection(self):
        log.info('closing-connection')
        self.exiting = True
        self.transport.loseConnection()

    def recv(self, predicate):
        assert self.connected
        return self.rx.get(predicate)

    def recv_any(self, new_framing):
        return self.recv(lambda _: True)

    def recv_xid(self, xid):
        return self.recv(lambda msg: msg.xid == xid)
