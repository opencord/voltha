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
from lxml import etree
from ncclient import manager
from ncclient.operations import RPCError
from ncclient.transport.errors import SSHError
from twisted.internet import defer, threads
from twisted.internet.defer import inlineCallbacks, returnValue

log = structlog.get_logger('ncclient')

ADTRAN_NS = 'http://www.adtran.com/ns/yang'


def adtran_module_url(module):
    return '{}/{}'.format(ADTRAN_NS, module)


def phys_entities_rpc():
    return """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <physical-entities-state xmlns="{}">
        <physical-entity/>
      </physical-entities-state>
    </filter>
    """.format(adtran_module_url('adtran-physical-entities'))


def _raises_rpc_error(message=""):
    def raises_rpc_error(func):
        def wrap_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except RPCError as e:
                log.exception(message, e=e)
                raise
        return wrap_func
    return raises_rpc_error


class AdtranNetconfClient(object):
    """
    Performs NETCONF requests
    """
    def __init__(self, host_ip, port=830, username='', password='', timeout=10):
        self._ip = host_ip
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._session = None

    def __str__(self):
        return "AdtranNetconfClient {}@{}:{}".format(self._username, self._ip, self._port)

    @property
    def capabilities(self):
        """
        Get the server's NETCONF capabilities

        :return: (ncclient.capabilities.Capabilities) object representing the server's capabilities.
        """
        return self._session.server_capabilities if self._session else None

    @property
    def connected(self):
        """
        Is this client connected to a NETCONF server
        :return: (boolean) True if connected
        """
        return self._session is not None and self._session.connected

    def connect(self, connect_timeout=None):
        """
        Connect to the NETCONF server

          o To disable attempting publickey authentication altogether, call with
            allow_agent and look_for_keys as False.

          o hostkey_verify enables hostkey verification from ~/.ssh/known_hosts

        :return: (deferred) Deferred request
        """
        timeout = connect_timeout or self._timeout

        return threads.deferToThread(self._do_connect, timeout)

    def _do_connect(self, timeout):
        try:
            self._session = manager.connect(host=self._ip,
                                            port=self._port,
                                            username=self._username,
                                            password=self._password,
                                            allow_agent=False,
                                            look_for_keys=False,
                                            hostkey_verify=False,
                                            timeout=timeout)

        except SSHError as e:
            # Log and rethrow exception so any errBack is called
            log.warn('SSHError-during-connect', e=e)
            raise e

        except Exception as e:
            # Log and rethrow exception so any errBack is called
            log.exception('Connect-failed: {}', e=e)
            raise e

        # If debug logging is enabled, decrease the level, DEBUG is a significant
        # performance hit during response XML decode

        if log.isEnabledFor('DEBUG'):
            log.setLevel('INFO')

        # TODO: ncclient also supports RaiseMode:NONE to limit exceptions.  To set use:
        #
        #  self._session.raise_mode = RaiseMode:NONE
        #
        # and the when you get a response back, you can check   'response.ok' to
        # see if it is 'True' if it is not, you can enumerate the 'response.errors'
        # list for more information

        return self._session

    def close(self):
        """
        Close the connection to the NETCONF server
        :return:  (deferred) Deferred request
        """
        s, self._session = self._session, None

        if s is None or not s.connected:
            return defer.returnValue(True)

        return threads.deferToThread(self._do_close, s)

    def _do_close(self, old_session):
        return old_session.close_session()

    @inlineCallbacks
    def _reconnect(self):
        try:
            yield self.close()
        except:
            pass

        try:
            yield self.connect()
        except:
            pass

    def get_config(self, source='running'):
        """
        Get the configuration from the specified source

        :param source: (string) Configuration source, 'running', 'candidate', ...

        :return: (deferred) Deferred request that wraps the GetReply class
        """
        self._check_session()

        return threads.deferToThread(self._do_get_config, source)

    def _do_get_config(self, source):
        """
        Get the configuration from the specified source

        :param source: (string) Configuration source, 'running', 'candidate', ...

        :return: (GetReply) The configuration.
        """
        return self._session.get_config(source)

    def get(self, payload):
        """
        Get the requested data from the server

        :param payload: Payload/filter
        :return: (deferred) for GetReply
        """
        log.debug('get', filter=payload)

        self._check_session()

        return threads.deferToThread(self._do_get, payload)

    @_raises_rpc_error('get')
    def _do_get(self, payload):
        """
        Get the requested data from the server

        :param payload: Payload/filter
        :return: (GetReply) response
        """
        log.debug('get', payload=payload)
        response = self._session.get(payload)
        # To get XML, use response.xml
        log.debug('response', response=response)

        return response

    def lock(self, source, lock_timeout):
        """
        Lock the configuration system
        :return: (deferred) for RpcReply
        """
        log.info('lock', source=source, timeout=lock_timeout)

        if not self._session or not self._session.connected:
            raise NotImplementedError('TODO: Support auto-connect if needed')

        return threads.deferToThread(self._do_lock, source, lock_timeout)

    @_raises_rpc_error('lock')
    def _do_lock(self, source, lock_timeout):
        """
        Lock the configuration system
        """
        response = self._session.lock(source, timeout=lock_timeout)
        # To get XML, use response.xml

        return response

    def unlock(self, source):
        """
        Get the requested data from the server
        :param source: RPC request

        :return: (deferred) for RpcReply
        """
        log.info('unlock', source=source)

        if not self._session or not self._session.connected:
            raise NotImplementedError('TODO: Support auto-connect if needed')

        return threads.deferToThread(self._do_unlock, source)

    @_raises_rpc_error('unlock')
    def _do_unlock(self, source):
        """
        Lock the configuration system
        """
        response = self._session.unlock(source)

        return response

    @inlineCallbacks
    def edit_config(self, config, target='running', default_operation='none',
                    test_option=None, error_option=None, ignore_delete_error=False):
        """
        Loads all or part of the specified config to the target configuration datastore
        with the ability to lock the datastore during the edit.

        :param config is the configuration, which must be rooted in the config element.
                      It can be specified either as a string or an Element.format="xml"
        :param target is the name of the configuration datastore being edited
        :param default_operation if specified must be one of { 'merge', 'replace', or 'none' }
        :param test_option if specified must be one of { 'test_then_set', 'set' }
        :param error_option if specified must be one of { 'stop-on-error',
                            'continue-on-error', 'rollback-on-error' } The
                            'rollback-on-error' error_option depends on the
                            :rollback-on-error capability.
        :param ignore_delete_error: (bool) For some startup deletes/clean-ups, we do a
                                    delete high up in the config to get whole lists. If
                                    these lists are empty, this helps suppress any error
                                    message from NETConf on failure to delete an empty list

        :return: (deferred) for RpcReply
        """
        if not self._session:
            raise NotImplementedError('No SSH Session')

        if not self._session.connected:
            try:
                yield self._reconnect()

            except Exception as e:
                log.exception('edit-config-connect', e=e)

        try:
            if config[:7] != '<config':
                config = '<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0"' + \
                         ' xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">' + \
                         config + '</config>'

            log.debug('netconf-request', config=config, target=target,
                      default_operation=default_operation)

            rpc_reply = yield threads.deferToThread(self._do_edit_config, target,
                                                    config)
        except Exception as e:
            if ignore_delete_error and 'operation="delete"' in config.lower():
                returnValue('ignoring-delete-error')
            log.exception('edit_config', e=e, config=config, target=target)
            raise

        returnValue(rpc_reply)

    def _do_edit_config(self, target, config, ignore_delete_error=False):
        """
        Perform actual edit-config operation
        """
        try:
            log.debug('edit-config', target=target, config=config)
            
            response = self._session.edit_config(target=target, config=config
                                                 # TODO: Support additional options later
                                                 # ,default_operation=default_operation,
                                                 # test_option=test_option,
                                                 # error_option=error_option
                                                 )

            log.debug('netconf-response', response=response)
            # To get XML, use response.xml
            # To check status, use response.ok  (boolean)

        except RPCError as e:
            if not ignore_delete_error or 'operation="delete"' not in config.lower():
                log.exception('do_edit_config', e=e, config=config, target=target)
            raise

        return response

    def rpc(self, rpc_string):
        """
        Custom RPC request
        :param rpc_string: (string) RPC request
        :return: (deferred) for GetReply
        """
        log.debug('rpc', rpc=rpc_string)

        self._check_session()

        return threads.deferToThread(self._do_rpc, rpc_string)

    def _do_rpc(self, rpc_string):
        try:
            response = self._session.dispatch(etree.fromstring(rpc_string))
            # To get XML, use response.xml

        except RPCError as e:
            log.exception('rpc', e=e)
            raise

        return response

    def _check_session(self):
        if not self._session:
            raise NotImplementedError('No SSH Session')
        if not self._session.connected:
            self._reconnect()
