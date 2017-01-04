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
import os
import rlcompleter
from pprint import pprint

import structlog
from twisted.conch import manhole_ssh
from twisted.conch.manhole import ColoredManhole
from twisted.conch.ssh import keys
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import Portal
from twisted.internet import reactor

log = structlog.get_logger()


MANHOLE_SERVER_RSA_PRIVATE = './manhole_rsa_key'
MANHOLE_SERVER_RSA_PUBLIC = './manhole_rsa_key.pub'


def get_rsa_keys():
    if not (os.path.exists(MANHOLE_SERVER_RSA_PUBLIC) and \
                    os.path.exists(MANHOLE_SERVER_RSA_PRIVATE)):
        # generate a RSA keypair
        log.info('generate-rsa-keypair')
        from Crypto.PublicKey import RSA
        rsa_key = RSA.generate(1024)
        public_key_str = rsa_key.publickey().exportKey(format='OpenSSH')
        private_key_str = rsa_key.exportKey()

        # save keys for next time
        file(MANHOLE_SERVER_RSA_PUBLIC, 'w+b').write(public_key_str)
        file(MANHOLE_SERVER_RSA_PRIVATE, 'w+b').write(private_key_str)
        log.debug('saved-rsa-keypair', public=MANHOLE_SERVER_RSA_PUBLIC,
                  private=MANHOLE_SERVER_RSA_PRIVATE)
    else:
        public_key_str = file(MANHOLE_SERVER_RSA_PUBLIC).read()
        private_key_str = file(MANHOLE_SERVER_RSA_PRIVATE).read()
    return public_key_str, private_key_str


class ManholeWithCompleter(ColoredManhole):

    def __init__(self, namespace):
        namespace['manhole'] = self
        super(ManholeWithCompleter, self).__init__(namespace)
        self.last_tab = None
        self.completer = rlcompleter.Completer(self.namespace)

    def handle_TAB(self):
        if self.last_tab != self.lineBuffer:
            self.last_tab = self.lineBuffer
            return

        buffer = ''.join(self.lineBuffer)
        completions = []
        maxlen = 3
        for c in xrange(1000):
            candidate = self.completer.complete(buffer, c)
            if not candidate:
                break

            if len(candidate) > maxlen:
                maxlen = len(candidate)

            completions.append(candidate)

        if len(completions) == 1:
            rest = completions[0][len(buffer):]
            self.terminal.write(rest)
            self.lineBufferIndex += len(rest)
            self.lineBuffer.extend(rest)

        elif len(completions):
            maxlen += 3
            numcols = self.width / maxlen
            self.terminal.nextLine()
            for idx, candidate in enumerate(completions):
                self.terminal.write('%%-%ss' % maxlen % candidate)
                if not ((idx + 1) % numcols):
                    self.terminal.nextLine()
            self.terminal.nextLine()
            self.drawInputLine()


class Manhole(object):

    def __init__(self, port, pws, **kw):
        kw.update(globals())
        kw['pp'] = pprint

        realm = manhole_ssh.TerminalRealm()
        manhole = ManholeWithCompleter(kw)

        def windowChanged(_, win_size):
            manhole.terminalSize(*reversed(win_size[:2]))

        realm.sessionFactory.windowChanged = windowChanged
        realm.chainedProtocolFactory.protocolFactory = lambda _: manhole
        portal = Portal(realm)
        portal.registerChecker(InMemoryUsernamePasswordDatabaseDontUse(**pws))
        factory = manhole_ssh.ConchFactory(portal)
        public_key_str, private_key_str = get_rsa_keys()
        factory.publicKeys = {
            'ssh-rsa': keys.Key.fromString(public_key_str)
        }
        factory.privateKeys = {
            'ssh-rsa': keys.Key.fromString(private_key_str)
        }
        reactor.listenTCP(port, factory, interface='localhost')


if __name__ == '__main__':
    Manhole(12222, dict(admin='admin'))
    reactor.run()
