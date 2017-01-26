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
import io
from lxml import etree
from lxml.builder import E
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from netconf.nc_rpc.rpc_factory import get_rpc_factory_instance
from netconf.constants import Constants as C
from netconf.nc_common.utils import qmap, ns, elm
import netconf.nc_common.error as ncerror
from netconf.nc_rpc.rpc_response import RpcResponse

log = structlog.get_logger()


class NetconfProtocolError(Exception): pass


class NetconfProtocolHandler:
    def __init__(self, nc_server, nc_conn, session, grpc_client, capabilities):
        self.started = True
        self.conn = nc_conn
        self.nc_server = nc_server
        self.grpc_client = grpc_client
        self.new_framing = False
        self.capabilities = capabilities
        self.session = session
        self.exiting = False
        self.connected = Deferred()
        self.connected.addCallback(self.nc_server.client_disconnected,
                                   self, None)

    def send_message(self, msg):
        self.conn.send_msg(C.XML_HEADER + msg, self.new_framing)

    def receive_message(self):
        return self.conn.receive_msg_any(self.new_framing)

    def send_hello(self, caplist, session=None):
        msg = elm(C.HELLO, attrib={C.XMLNS: ns(C.NC)})
        caps = E.capabilities(*[E.capability(x) for x in caplist])
        msg.append(caps)

        if session is not None:
            msg.append(E(C.SESSION_ID, str(session.session_id)))
        msg = etree.tostring(msg)
        log.info("Sending HELLO", msg=msg)
        msg = msg.decode('utf-8')
        self.send_message(msg)

    def send_rpc_reply(self, rpc_reply, origmsg):
        reply = etree.Element(qmap(C.NC) + C.RPC_REPLY, attrib=origmsg.attrib,
                              nsmap=origmsg.nsmap)
        try:
            rpc_reply.getchildren
            reply.append(rpc_reply)
        except AttributeError:
            reply.extend(rpc_reply)
        ucode = etree.tounicode(reply, pretty_print=True)
        log.info("RPC-Reply", reply=ucode)
        self.send_message(ucode)

    def send_custom_rpc_reply(self, rpc_reply, origmsg):
        reply = etree.Element(qmap(C.NC) + C.RPC_REPLY, attrib=origmsg.attrib,
                              nsmap=rpc_reply.nsmap)
        try:
            reply.extend(rpc_reply.getchildren())
        except AttributeError:
            reply.extend(rpc_reply)
        ucode = etree.tounicode(reply, pretty_print=True)
        log.info("Custom-RPC-Reply", reply=ucode)
        self.send_message(ucode)

    def set_framing_version(self):
        if C.NETCONF_BASE_11 in self.capabilities.client_caps:
            self.new_framing = True
        elif C.NETCONF_BASE_10 not in self.capabilities.client_caps:
            raise SessionError(
                "Client doesn't implement 1.0 or 1.1 of netconf")

    @inlineCallbacks
    def open_session(self):
        # The transport should be connected at this point.
        try:
            # Send hello message.
            yield self.send_hello(self.capabilities.server_caps, self.session)
            # Get reply
            reply = yield self.receive_message()
            log.info("reply-received", reply=reply)

            # Parse reply
            tree = etree.parse(io.BytesIO(reply.encode('utf-8')))
            root = tree.getroot()
            caps = root.xpath(C.CAPABILITY_XPATH, namespaces=C.NS_MAP)

            # Store capabilities
            for cap in caps:
                self.capabilities.add_client_capability(cap.text)

            self.set_framing_version()
            self.session.session_opened = True

            log.info('session-opened', session_id=self.session.session_id,
                     framing="1.1" if self.new_framing else "1.0")
        except Exception as e:
            log.exception('hello-failure', e=e)
            self.stop(repr(e))
            raise

    @inlineCallbacks
    def start(self):
        log.info('starting')

        try:
            yield self.open_session()
            while True:
                if not self.session.session_opened:
                    break;
                msg = yield self.receive_message()
                yield self.handle_request(msg)

        except Exception as e:
            log.exception('exception', exception=repr(e))
            self.stop(repr(e))

        log.info('shutdown')
        returnValue(self)

    @inlineCallbacks
    def handle_request(self, msg):
        if not self.session.session_opened:
            return

        # Any error with XML encoding here is going to cause a session close
        try:
            tree = etree.parse(io.BytesIO(msg.encode('utf-8')))
            if not tree:
                raise ncerror.SessionError(msg, "Invalid XML from client.")
        except etree.XMLSyntaxError:
            log.error("malformed-message", msg=msg)
            try:
                error = ncerror.BadMsg(msg)
                self.send_message(error.get_reply_msg())
            except AttributeError:
                log.error("attribute-error", msg=msg)
                # close session
                self.close()
            return

        rpcs = tree.xpath(C.RPC_XPATH, namespaces=C.NS_MAP)
        if not rpcs:
            raise ncerror.SessionError(msg, "No rpc found")

        # A message can have multiple rpc requests
        rpc_factory = get_rpc_factory_instance()
        for rpc in rpcs:
            try:
                # Validate message id is received
                try:
                    msg_id = rpc.get(C.MESSAGE_ID)
                    log.info("Received-rpc-message-id", msg_id=msg_id)
                except (TypeError, ValueError):
                    log.error('no-message-id', rpc=rpc)
                    raise ncerror.MissingElement(msg, C.MESSAGE_ID)

                # Get a rpc handler
                rpc_handler = rpc_factory.get_rpc_handler(rpc,
                                                          msg,
                                                          self.grpc_client,
                                                          self.session,
                                                          self.capabilities)
                if rpc_handler:
                    # set the parameters for this handler
                    response = yield rpc_handler.execute()
                    log.info('handler',
                             rpc_handler=rpc_handler,
                             is_error=response.is_error,
                             custom_rpc=response.custom_rpc,
                             response=response)
                    if not response.is_error:
                        if response.custom_rpc:
                            self.send_custom_rpc_reply(response.node, rpc)
                        else:
                            self.send_rpc_reply(response.node, rpc)
                            # self.send_rpc_reply(self.get_mock_volthainstance(), rpc)
                    else:
                        self.send_message(response.node.get_xml_reply())

                    if response.close_session:
                        log.info('response-closing-session', response=response)
                        self.close()
                else:
                    log.error('no-rpc-handler',
                              request=msg,
                              session_id=self.session.session_id)
                    error = ncerror.NotImpl(rpc)
                    self.send_message(error.get_xml_reply())

            except ncerror.BadMsg as err:
                log.info('ncerror.BadMsg')
                if self.new_framing:
                    self.send_message(err.get_xml_reply())
                else:
                    # If we are 1.0 we have to simply close the connection
                    # as we are not allowed to send this error
                    log.error("Closing-1-0-session--malformed-message")
                    self.close()
            except (ncerror.NotImpl, ncerror.MissingElement) as e:
                log.exception('error', e=e)
                self.send_message(e.get_reply_msg())
            except Exception as e:
                log.exception('Exception', e=e)
                error = ncerror.ServerException(rpc, e)
                self.send_message(error.get_xml_reply())

    def stop(self, reason):
        if not self.exiting:
            log.debug('stopping')
            self.exiting = True
            if self.session.session_opened:
                # TODO: send a closing message to the far end
                self.conn.close_connection()
            self.nc_server.session_mgr.remove_session(self.session)
            self.session.session_opened = False
            self.connected.callback(None)
            log.info('stopped')

    def close(self):
        if not self.exiting:
            log.debug('closing-client')
            self.exiting = True
            if self.session.session_opened:
                self.conn.close_connection()
            self.nc_server.session_mgr.remove_session(self.session)
            self.session.session_opened = False
            self.connected.callback(None)
            log.info('closing-client')

    # Example of a properly formatted Yang-XML message
    def get_mock_volthainstance(self):
        res = {'log_level': 'INFO',
               'device_types': [
                   {'adapter': u'broadcom_onu',
                    'accepts_bulk_flow_update': True,
                    'id': u'broadcom_onu',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'maple_olt',
                    'accepts_bulk_flow_update': True,
                    'id': u'maple_olt',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'ponsim_olt',
                    'accepts_bulk_flow_update': True,
                    'id': u'ponsim_olt',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'ponsim_onu',
                    'accepts_bulk_flow_update': True,
                    'id': u'ponsim_onu',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'simulated_olt',
                    'accepts_bulk_flow_update': True,
                    'id': u'simulated_olt',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'simulated_onu',
                    'accepts_bulk_flow_update': True,
                    'id': u'simulated_onu',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'tibit_olt',
                    'accepts_bulk_flow_update': True,
                    'id': u'tibit_olt',
                    'accepts_add_remove_flow_updates': False
                    },
                   {'adapter': u'tibit_onu',
                    'accepts_bulk_flow_update': True,
                    'id': u'tibit_onu',
                    'accepts_add_remove_flow_updates': False}
               ],
               'logical_devices': [],
               'devices': [],
               'instance_id': u'compose_voltha_1',
               'version': u'0.9.0',
               'health': {'state': 'HEALTHY'},
               'device_groups': [],
               'adapters': [
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Voltha project',
                    'id': u'broadcom_onu',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Voltha project',
                    'id': u'maple_olt',
                    'logical_device_ids': []},
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.4',
                    'vendor': u'Voltha project',
                    'id': u'ponsim_olt',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.4',
                    'vendor': u'Voltha project',
                    'id': u'ponsim_onu',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Voltha project',
                    'id': u'simulated_olt',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Voltha project',
                    'id': u'simulated_onu',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Tibit Communications Inc.',
                    'id': u'tibit_olt',
                    'logical_device_ids': []
                    },
                   {'config': {'log_level': 'INFO'},
                    'version': u'0.1',
                    'vendor': u'Tibit Communications Inc.',
                    'id': u'tibit_onu',
                    'logical_device_ids': []
                    }
               ]
               }
        devices_array = []
        flow_items = []
        for i in xrange(1, 10):
            flow_items.append({
                'items': {
                    'id': str(i),
                    'table_id': 'table_id_' + str(i),
                    'flags': i,
                    'instructions': [
                        {'type': i, 'goto_table': 'table_id_' + str(i)},
                        {'type': i, 'meter': i},
                        {'type': i,
                         'actions': {'actions': [
                             {'type': 11,
                              'output': {
                                  'port': i,
                                  'max_len': i}
                              }
                         ]}
                         }
                    ]
                }
            }
            )
        for i in xrange(1, 10):
            devices_array.append({
                'id': str(i),
                'type': 'type_' + str(i),
                'vlan': i,
                'flows': flow_items
            })
        res['devices'] = devices_array
        xml = dicttoxml.dicttoxml(res, attr_type=True)
        root = etree.fromstring(xml)
        # print etree.tounicode(root, pretty_print=True)
        request = {'class': 'VolthaInstance'}
        top = RpcResponse().build_yang_response(root, request)
        return top
