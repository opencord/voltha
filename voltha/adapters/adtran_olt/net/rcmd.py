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

import structlog
from twisted.internet.defer import Deferred, succeed
from twisted.internet.protocol import Factory, Protocol
from twisted.conch.client.knownhosts import ConsoleUI, KnownHostsFile
from twisted.conch.endpoints import SSHCommandClientEndpoint
from twisted.internet import reactor

log = structlog.get_logger()
_open = open


class RCmd(object):
    """
    Execute a one-time remote command via SSH
    """
    def __init__(self, host, username, password,
                 command,
                 port=None,
                 keys=None,
                 known_hosts=None,
                 agent=None):
        self.reactor = reactor
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.keys = keys
        # self.knownHosts = known_hosts
        self.knownHosts = known_hosts
        self.agent = agent
        self.command = command
        self.ui = RCmd.FixedResponseUI(True)

    class NoiseProtocol(Protocol):
        def __init__(self):
            self.finished = Deferred()
            self.strings = ["bif", "pow", "zot"]

        def connectionMade(self):
            log.debug('connection-made')
            self._send_noise()

        def _send_noise(self):
            if self.strings:
                self.transport.write(self.strings.pop(0) + "\n")
            else:
                self.transport.loseConnection()

        def dataReceived(self, data):
            log.debug('rx', data=data)
            if self.finished is not None and not self.finished.called:
                self.finished.callback(data)
            self._send_noise()

        def connectionLost(self, reason):
            log.debug('connection-lost')
            if not self.finished.called:
                self.finished.callback(reason)

    class PermissiveKnownHosts(KnownHostsFile):
        def verifyHostKey(self, ui, hostname, ip, key):
            log.debug('verifyHostKey')
            return True

    class FixedResponseUI(ConsoleUI):
        def __init__(self, result):
            super(RCmd.FixedResponseUI, self).__init__(lambda: _open("/dev/null",
                                                                     "r+b",
                                                                     buffering=0))
            self.result = result

        def prompt(self, _):
            log.debug('prompt')
            return succeed(True)

        def warn(self, text):
            log.debug('warn')
            pass

    def _endpoint_for_command(self, command):
        return SSHCommandClientEndpoint.newConnection(
            self.reactor, command, self.username, self.host,
            port=self.port,
            password=self.password,
            keys=self.keys,
            agentEndpoint=self.agent,
            knownHosts=self.knownHosts,
            ui=self.ui
        )

    def execute(self):
        endpoint = self._endpoint_for_command(self.command)
        factory = Factory()
        factory.protocol = RCmd.NoiseProtocol

        d = endpoint.connect(factory)
        d.addCallback(lambda proto: proto.finished)
        return d
