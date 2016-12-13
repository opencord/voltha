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


class RpcFactory:

	instance = None

	def __init__(self):
		self.rpc_map = {}
		#TODO:  This will be loaded after the yang modules have been
		# generated from proto files
		self.register_rpc('{urn:opencord:params:xml:ns:voltha:ietf-voltha}',
						 'VolthaGlobalService', 'GetVoltha', GetVoltha)

	def _get_key(self, namespace, service, name):
		return ''.join([namespace,service,name])

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
			msg_id = rpc_node.get('message-id')
			log.info("Received-rpc-message-id", msg_id=msg_id)

		except (TypeError, ValueError):
			raise ncerror.SessionError(msg,
									   "No valid message-id attribute found")

		log.info("rpc-node", node=etree.tostring(rpc_node, pretty_print=True))

		# Get the first child of rpc as the method name
		rpc_method = rpc_node.getchildren()
		if len(rpc_method) != 1:
			log.error("badly-formatted-rpc-method", msg_id=msg_id)
			raise ncerror.BadMsg(rpc_node)

		rpc_method = rpc_method[0]

		if rpc_method.prefix is None:
			log.error("rpc-method-has-no-prefix", msg_id=msg_id)
			raise ncerror.BadMsg(rpc_node)

		try:
			# extract the namespace, service and name
			namespace = ''.join(['{', rpc_method.nsmap[rpc_method.prefix], '}'])
			# rpc_name = rpc_method.tag.replace(qmap('nc'), "")
			rpc = rpc_method.tag.replace(namespace, "").split('-')
			rpc_service = rpc[0]
			rpc_name = rpc[1]
			log.info("rpc-request",
					 namespace=namespace,
					 service=rpc_service,
					 name=rpc_name)
		except Exception as e:
			log.error("rpc-parsing-error", exception=repr(e))
			raise ncerror.BadMsg(rpc_node)

		class_handler = self.get_handler(namespace, rpc_service, rpc_name)

		# class_handler = self.rpc_class_handlers.get(rpc_name, None)
		if class_handler is not None:
			return class_handler(rpc_node, rpc_method, grpc_channel, session)

		log.error("rpc-not-implemented", rpc=rpc_name)


	rpc_class_handlers = {
		'getvoltha' : GetVoltha,
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


if __name__ == '__main__':
   fac = get_rpc_factory_instance()
   fac.register_rpc('urn:opencord:params:xml:ns:voltha:ietf-voltha',
					'VolthaGlobalService', 'GetVoltha', GetVoltha)
   rpc = fac.get_handler('urn:opencord:params:xml:ns:voltha:ietf-voltha',
					'VolthaGlobalService', 'GetVoltha')
   # rpc = fac.rpc_class_handlers.get('getvoltha', None)
   print rpc(None,None,None, None)