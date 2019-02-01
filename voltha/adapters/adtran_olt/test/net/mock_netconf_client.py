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
import random
import time
from voltha.adapters.adtran_olt.net.adtran_netconf import AdtranNetconfClient
from common.utils.asleep import asleep
from ncclient.operations.rpc import RPCReply, RPCError
from ncclient.operations.retrieve import GetReply
from twisted.internet.defer import inlineCallbacks, returnValue

log = structlog.get_logger()

_dummy_xml = '<rpc-reply message-id="br-549" ' + \
      'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" ' + \
      'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">' + \
      '<data/>' + \
      '</rpc-reply>'


class MockNetconfClient(AdtranNetconfClient):
    """
    Performs NETCONF requests
    """
    def __init__(self, host_ip, port=830, username='', password='', timeout=20):
        super(MockNetconfClient, self).__init__(host_ip, port=port, username=username,
                                                password=password, timeout=timeout)
        self._connected = False
        self._locked = {}

    def __str__(self):
        return "MockNetconfClient {}@{}:{}".format(self._username, self._ip, self._port)

    @property
    def capabilities(self):
        """
        Get the server's NETCONF capabilities

        :return: (ncclient.capabilities.Capabilities) object representing the server's capabilities.
        """
        return None

    @property
    def connected(self):
        """
        Is this client connected to a NETCONF server
        :return: (boolean) True if connected
        """
        return self._connected

    @inlineCallbacks
    def connect(self, connect_timeout=None):
        """
        Connect to the NETCONF server
          o To disable attempting publickey authentication altogether, call with
            allow_agent and look_for_keys as False.`

          o hostkey_verify enables hostkey verification from ~/.ssh/known_hosts

        :return: (deferred) Deferred request
        """
        yield asleep(random.uniform(0.01, 0.05))   # Simulate NETCONF request delay
        self._connected = True
        self._locked = {}
        returnValue(True)

    @inlineCallbacks
    def close(self):
        """
        Close the connection to the NETCONF server
        :return:  (deferred) Deferred request
        """
        yield asleep(random.uniform(0.01, 0.05))   # Simulate NETCONF request delay
        self._connected = False
        self._locked = {}
        returnValue(True)

    @inlineCallbacks
    def get_config(self, source='running'):
        """
        Get the configuration from the specified source

        :param source: (string) Configuration source, 'running', 'candidate', ...
        :return: (deferred) Deferred request that wraps the GetReply class
        """
        yield asleep(random.uniform(0.01, 0.04))   # Simulate NETCONF request delay

        # TODO: Customize if needed...
        xml = _dummy_xml
        returnValue(GetReply(xml))

    @inlineCallbacks
    def get(self, payload):
        """
        Get the requested data from the server

        :param payload: Payload/filter
        :return: (deferred) for GetReply
        """
        yield asleep(random.uniform(0.01, 0.03))   # Simulate NETCONF request delay

        # TODO: Customize if needed...
        xml = _dummy_xml
        returnValue(GetReply(xml))

    @inlineCallbacks
    def lock(self, source, lock_timeout):
        """
        Lock the configuration system
        :param source: is the name of the configuration datastore accessed
        :param lock_timeout: timeout in seconds for holding the lock
        :return: (defeered) for RpcReply
        """
        expire_time = time.time() + lock_timeout

        if source not in self._locked:
            self._locked[source] = None

        while self._locked[source] is not None:
            # Watch for lock timeout
            if time.time() >= self._locked[source]:
                self._locked[source] = None
                break
            yield asleep(0.1)

        if time.time() < expire_time:
            yield asleep(random.uniform(0.01, 0.05))   # Simulate NETCONF request delay
            self._locked[source] = expire_time

        returnValue(RPCReply(_dummy_xml) if expire_time > time.time() else RPCError('TODO'))

    @inlineCallbacks
    def unlock(self, source):
        """
        Get the requested data from the server
        :param rpc_string: RPC request
        :param source: is the name of the configuration datastore accessed
        :return: (defeered) for RpcReply
        """
        if source not in self._locked:
            self._locked[source] = None

        if self._locked[source] is not None:
            yield asleep(random.uniform(0.01, 0.05))   # Simulate NETCONF request delay

        self._locked[source] = None
        returnValue(RPCReply(_dummy_xml))

    @inlineCallbacks
    def edit_config(self, config, target='running', default_operation='merge',
                    test_option=None, error_option=None, ignore_delete_error=False):
        """
        Loads all or part of the specified config to the target configuration datastore with the ability to lock
        the datastore during the edit.

        :param config is the configuration, which must be rooted in the config element. It can be specified
                      either as a string or an Element.format="xml"
        :param target is the name of the configuration datastore being edited
        :param default_operation if specified must be one of { 'merge', 'replace', or 'none' }
        :param test_option if specified must be one of { 'test_then_set', 'set' }
        :param error_option if specified must be one of { 'stop-on-error', 'continue-on-error', 'rollback-on-error' }
                            The 'rollback-on-error' error_option depends on the :rollback-on-error capability.
        :param ignore_delete_error: (bool) For some startup deletes/clean-ups, we do a
                                    delete high up in the config to get whole lists. If
                                    these lists are empty, this helps suppress any error
                                    message from NETConf on failure to delete an empty list
        :return: (deferred) for RpcReply
        """
        try:
            yield asleep(random.uniform(0.01, 0.02))  # Simulate NETCONF request delay

        except Exception as e:
            if ignore_delete_error and 'operation="delete"' in config.lower():
                returnValue('ignoring-delete-error')
            log.exception('edit_config', e=e)
            raise

        # TODO: Customize if needed...
        xml = _dummy_xml
        returnValue(RPCReply(xml))

    @inlineCallbacks
    def rpc(self, rpc_string):
        """
        Custom RPC request
        :param rpc_string: (string) RPC request
        :return: (defeered) for GetReply
        """
        yield asleep(random.uniform(0.01, 0.02))   # Simulate NETCONF request delay

        # TODO: Customize if needed...
        xml = _dummy_xml
        returnValue(RPCReply(xml))
