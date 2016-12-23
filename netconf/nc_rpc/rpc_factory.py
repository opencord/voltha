#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
#
# Code adapted from https://github.com/choppsv1/netconf
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
from base.commit import Commit
from base.copy_config import CopyConfig
from base.delete_config import DeleteConfig
from base.discard_changes import DiscardChanges
from base.edit_config import EditConfig
from base.get import Get
from base.get_config import GetConfig
from base.lock import Lock
from base.unlock import UnLock
from base.close_session import CloseSession
from base.kill_session import KillSession
from ext.get_voltha import GetVoltha
from netconf import NSMAP, qmap
import netconf.nc_common.error as ncerror

log = structlog.get_logger()
from lxml import etree

ns_map = {
    'base': '{urn:ietf:params:xml:ns:netconf:base:1.0}',
    'voltha': '{urn:opencord:params:xml:ns:voltha:ietf-voltha}'
}


class RpcFactory:
    instance = None

    def __init__(self):
        self.rpc_map = {}
        # TODO:  This will be loaded after the yang modules have been
        # generated from proto files
        self.register_rpc('{urn:opencord:params:xml:ns:voltha:ietf-voltha}',
                          'VolthaGlobalService', 'GetVoltha', GetVoltha)
        self.register_rpc('{urn:opencord:params:xml:ns:voltha:ietf-voltha}',
                          'any', 'any', GetVoltha)

    def _get_key(self, namespace, service, name):
        return ''.join([namespace, service, name])

    def get_attribute_value(self, name, attributes):
        for tup in attributes.items():
            if tup[0] == name:
                return tup[1]

    # Parse a request (node is an ElementTree) and return a dictionary
    # TODO:  This parser is specific to a GET request.  Need to be it more
    # generic
    def parse_xml_request(self, node):
        request = {}
        if not len(node):
            return request
        for elem in node.iter():
            if elem.tag.find(ns_map['base']) != -1:  # found
                elem_name = elem.tag.replace(ns_map['base'], "")
                if elem_name == 'rpc':
                    request['type'] = 'rpc'
                    request['message_id'] = self.get_attribute_value(
                        'message-id', elem.attrib)
                elif elem_name == 'filter':
                    request['filter'] = self.get_attribute_value('type',
                                                                 elem.attrib)
                else:
                    request[
                        'command'] = elem_name  # attribute is empty for now
            elif elem.tag.find(ns_map['voltha']) != -1:  # found
                if request.has_key('class'):
                    request['subclass'] = elem.tag.replace(ns_map['voltha'],
                                                           "")
                else:
                    request['class'] = elem.tag.replace(ns_map['voltha'], "")
        return request

    def register_rpc(self, namespace, service, name, klass):
        key = self._get_key(namespace, service, name)
        if key not in self.rpc_map.keys():
            self.rpc_map[key] = klass

    def get_handler(self, namespace, service, name):
        key = self._get_key(namespace, service, name)
        if key in self.rpc_map.keys():
            return self.rpc_map[key]

    def get_rpc_handler(self, rpc_node, msg, grpc_channel, session):
        try:
            # Parse the request into a dictionary
            log.info("rpc-node",
                     node=etree.tostring(rpc_node, pretty_print=True))

            request = self.parse_xml_request(rpc_node)
            if not request:
                log.error("request-bad-format")
                raise ncerror.BadMsg(rpc_node)

            if not request.has_key('message_id') or \
                    not request.has_key('command'):
                log.error("request-no-message-id")
                raise ncerror.BadMsg(rpc_node)

            log.info("parsed-request", request=request)

            class_handler = self.rpc_class_handlers.get(request['command'],
                                                        None)
            if class_handler is not None:
                return class_handler(request, grpc_channel, session)

            log.error("rpc-not-implemented", rpc=request['command'])

        except Exception as e:
            raise ncerror.BadMsg(rpc_node)

    rpc_class_handlers = {
        'getvoltha': GetVoltha,
        'get-config': GetConfig,
        'get': Get,
        'edit-config': EditConfig,
        'copy-config': CopyConfig,
        'delete-config': DeleteConfig,
        'commit': Commit,
        'lock': Lock,
        'unlock': UnLock,
        'close-session': CloseSession,
        'kill-session': KillSession
    }


def get_rpc_factory_instance():
    if RpcFactory.instance == None:
        RpcFactory.instance = RpcFactory()
    return RpcFactory.instance
