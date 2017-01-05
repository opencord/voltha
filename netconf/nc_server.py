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
import sys
import os
from twisted.conch import avatar
from twisted.cred import portal
from twisted.conch.checkers import SSHPublicKeyChecker, InMemorySSHKeyDB
from twisted.conch.ssh import factory, userauth, connection, keys, session
from twisted.conch.ssh.transport import SSHServerTransport

from twisted.cred.checkers import FilePasswordDB
from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks
# from twisted.python import log as logp
from zope.interface import implementer
from session.nc_protocol_handler import NetconfProtocolHandler
from session.nc_connection import NetconfConnection
from session.session_mgr import get_session_manager_instance
from constants import Constants as C
from capabilities import Capabilities

dir_path = os.path.dirname(os.path.realpath(__file__))

# logp.startLogging(sys.stderr)

log = structlog.get_logger()


# @implementer(conchinterfaces.ISession)
class NetconfAvatar(avatar.ConchUser):
    def __init__(self, username, nc_server, grpc_client):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.nc_server = nc_server
        self.grpc_client = grpc_client
        self.channelLookup.update({'session': session.SSHSession})
        self.subsystemLookup.update(
            {b"netconf": NetconfConnection})

    def get_grpc_client(self):
        return self.grpc_client

    def get_nc_server(self):
        return self.nc_server

    def get_user(self):
        return self.username

    def logout(self):
        log.info('netconf-avatar-logout', username=self.username)


@implementer(portal.IRealm)
class NetconfRealm(object):
    def __init__(self, nc_server, grpc_client):
        self.grpc_client = grpc_client
        self.nc_server = nc_server

    def requestAvatar(self, avatarId, mind, *interfaces):
        user = NetconfAvatar(avatarId, self.nc_server, self.grpc_client)
        return interfaces[0], user, user.logout


class NCServer(factory.SSHFactory):
    #
    services = {
        'ssh-userauth': userauth.SSHUserAuthServer,
        'ssh-connection': connection.SSHConnection
    }

    def __init__(self,
                 netconf_port,
                 server_private_key_file,
                 server_public_key_file,
                 client_public_keys_file,
                 client_passwords_file,
                 grpc_client):

        self.netconf_port = netconf_port
        self.server_private_key_file = server_private_key_file
        self.server_public_key_file = server_public_key_file
        self.client_public_keys_file = client_public_keys_file
        self.client_passwords_file = client_passwords_file
        self.session_mgr = get_session_manager_instance()
        self.grpc_client = grpc_client
        self.capabilities = Capabilities()
        self.connector = None
        self.nc_client_map = {}
        self.running = False
        self.exiting = False

    def start(self):
        log.debug('starting')
        if self.running:
            return
        self.running = True
        reactor.callLater(0, self.start_ssh_server)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        self.exiting = True
        self.connector.disconnect()
        self.d_stopped.callback(None)
        log.info('stopped')

    def set_capabilities(self):
        yang_schemas = self.grpc_client.yang_schemas
        if not yang_schemas:
            log.error('no-yang-schema')
            return
        self.capabilities.set_server_capabilities(yang_schemas)
        self.capabilities.set_schema_dir(self.grpc_client.work_dir)

    def reload_capabilities(self):
        # TODO: Called when there is a reconnect to voltha
        # If there are new device types then the new
        # capabilities will be exposed for subsequent client connections to use
        pass

    def client_disconnected(self, result, handler, reason):
        assert isinstance(handler, NetconfProtocolHandler)

        log.info('client-disconnected', reason=reason)

        # For now just nullify the handler
        handler.close()

    def client_connected(self, client_conn):
        assert isinstance(client_conn, NetconfConnection)
        log.info('client-connected')

        #create a session
        session = self.session_mgr.create_session(client_conn.avatar.get_user())
        handler = NetconfProtocolHandler(self, client_conn,
                                         session, self.grpc_client,
                                         self.capabilities)
        client_conn.proto_handler = handler
        reactor.callLater(0, handler.start)

    def setup_secure_access(self):
        try:
            from twisted.cred import portal
            portal = portal.Portal(NetconfRealm(self, self.grpc_client))

            # setup userid-password access
            password_file = '{}/{}/{}'.format(dir_path,
                                              C.CLIENT_CRED_DIRECTORY,
                                              self.client_passwords_file)
            portal.registerChecker(FilePasswordDB(password_file))

            # setup access when client uses keys
            keys_file = '{}/{}/{}'.format(dir_path,
                                          C.CLIENT_CRED_DIRECTORY,
                                          self.client_public_keys_file)
            with open(keys_file) as f:
                users = [line.rstrip('\n') for line in f]
            users_dict = {}
            for user in users:
                users_dict[user.split(':')[0]] = [
                    keys.Key.fromFile('{}/{}/{}'.format(dir_path,
                                                        C.CLIENT_CRED_DIRECTORY,
                                                        user.split(':')[1]))]
            sshDB = SSHPublicKeyChecker(InMemorySSHKeyDB(users_dict))
            portal.registerChecker(sshDB)
            return portal
        except Exception as e:
            log.error('setup-secure-access-fail', exception=repr(e))

    @inlineCallbacks
    def start_ssh_server(self):
        try:
            log.debug('starting', port=self.netconf_port)
            self.set_capabilities()
            self.portal = self.setup_secure_access()
            self.connector = reactor.listenTCP(self.netconf_port, self)
            log.debug('started', port=self.netconf_port)
            self.d_stopped = Deferred()
            self.d_stopped.callback(self.stop)
            yield self.d_stopped
        except Exception as e:
            log.error('netconf-server-not-started', port=self.netconf_port,
                      exception=repr(e))

    # Methods from SSHFactory
    #

    def protocol(self):
        return SSHServerTransport()

    def getPublicKeys(self):
        key_file_name = '{}/{}/{}'.format(dir_path,
                                          C.KEYS_DIRECTORY,
                                          self.server_public_key_file)
        try:
            publicKeys = {
                'ssh-rsa': keys.Key.fromFile(key_file_name)
            }
            return publicKeys
        except Exception as e:
            log.error('cannot-retrieve-server-public-key',
                      filename=key_file_name, exception=repr(e))

    def getPrivateKeys(self):
        key_file_name = '{}/{}/{}'.format(dir_path,
                                          C.KEYS_DIRECTORY,
                                          self.server_private_key_file)
        try:
            privateKeys = {
                'ssh-rsa': keys.Key.fromFile(key_file_name)
            }
            return privateKeys
        except Exception as e:
            log.error('cannot-retrieve-server-private-key',
                      filename=key_file_name, exception=repr(e))
