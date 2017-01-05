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
            log.error('hello-failure', exception=repr(e))
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
                             response=response)
                    self.send_rpc_reply(response.node, rpc)
                    # self.send_rpc_reply(self.get_instance(), rpc)

                    if response.close_session:
                        log.info('response-closing-session', response=response)
                        self.close()
                else:
                    log.error('no-rpc-handler',
                              request=msg,
                              session_id=self.session.session_id)
                    raise ncerror.NotImpl(msg)

            except ncerror.BadMsg as err:
                log.info('ncerror.BadMsg')
                if self.new_framing:
                    self.send_message(err.get_reply_msg())
                else:
                    # If we are 1.0 we have to simply close the connection
                    # as we are not allowed to send this error
                    log.error("Closing-1-0-session--malformed-message")
                    self.close()
            except (ncerror.NotImpl, ncerror.MissingElement) as e:
                log.info('error', repr(e))
                self.send_message(e.get_reply_msg())
            except Exception as ex:
                log.info('Exception', repr(ex))
                error = ncerror.ServerException(rpc, ex)
                self.send_message(error.get_reply_msg())


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
    def get_instance(self):
        xml_string = """
            <data>
             <Voltha xmlns="urn:opencord:params:xml:ns:voltha:ietf-voltha">
             <instances>
              <log_level>INFO</log_level>
                <device_types>
                  <adapter>simulated_onu</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>simulated_onu</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <device_types>
                  <adapter>tibit_onu</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>tibit_onu</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <device_types>
                  <adapter>maple_olt</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>maple_olt</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <device_types>
                  <adapter>tibit_olt</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>tibit_olt</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <device_types>
                  <adapter>broadcom_onu</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>broadcom_onu</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <device_types>
                  <adapter>simulated_olt</adapter>
                  <accepts_bulk_flow_update>True</accepts_bulk_flow_update>
                  <id>simulated_olt</id>
                  <accepts_add_remove_flow_updates>False</accepts_add_remove_flow_updates>
                </device_types>
                <logical_devices>
                  <datapath_id>1</datapath_id>
                  <root_device_id>simulated_olt_1</root_device_id>
                  <switch_features>
                    <auxiliary_id>0</auxiliary_id>
                    <n_tables>2</n_tables>
                    <datapath_id>0</datapath_id>
                    <capabilities>15</capabilities>
                    <n_buffers>256</n_buffers>
                  </switch_features>
                  <flows/>
                  <id>simulated1</id>
                  <flow_groups/>
                    <ports>
                      <device_port_no>2</device_port_no>
                      <root_port>False</root_port>
                      <device_id>simulated_onu_1</device_id>
                      <id>onu1</id>
                      <ofp_port>
                        <hw_addr>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>1</item>
                        </hw_addr>
                        <curr_speed>32</curr_speed>
                        <curr>4128</curr>
                        <name>onu1</name>
                        <supported>0</supported>
                        <state>4</state>
                        <max_speed>32</max_speed>
                        <advertised>4128</advertised>
                        <peer>4128</peer>
                        <config>0</config>
                        <port_no>1</port_no>
                      </ofp_port>
                    </ports>
                    <ports>
                      <device_port_no>2</device_port_no>
                      <root_port>False</root_port>
                      <device_id>simulated_onu_2</device_id>
                      <id>onu2</id>
                      <ofp_port>
                        <hw_addr>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>2</item>
                        </hw_addr>
                        <curr_speed>32</curr_speed>
                        <curr>4128</curr>
                        <name>onu2</name>
                        <supported>0</supported>
                        <state>4</state>
                        <max_speed>32</max_speed>
                        <advertised>4128</advertised>
                        <peer>4128</peer>
                        <config>0</config>
                        <port_no>2</port_no>
                      </ofp_port>
                    </ports>
                    <ports>
                      <device_port_no>2</device_port_no>
                      <root_port>True</root_port>
                      <device_id>simulated_olt_1</device_id>
                      <id>olt1</id>
                      <ofp_port>
                        <hw_addr>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>0</item>
                          <item>129</item>
                        </hw_addr>
                        <curr_speed>32</curr_speed>
                        <curr>4128</curr>
                        <name>olt1</name>
                        <supported>0</supported>
                        <state>4</state>
                        <max_speed>32</max_speed>
                        <advertised>4128</advertised>
                        <peer>4128</peer>
                        <config>0</config>
                        <port_no>129</port_no>
                      </ofp_port>
                    </ports>
                  <desc>
                    <dp_desc>n/a</dp_desc>
                    <sw_desc>simualted pon</sw_desc>
                    <hw_desc>simualted pon</hw_desc>
                    <serial_num>985c4449d50a441ca843401e2f44e682</serial_num>
                    <mfr_desc>cord porject</mfr_desc>
                  </desc>
                </logical_devices>
              <devices>
                <item>
                  <vendor>simulated</vendor>
                  <parent_port_no>0</parent_port_no>
                  <software_version>1.0</software_version>
                  <connect_status>UNKNOWN</connect_status>
                  <type>simulated_olt</type>
                  <adapter>simulated_olt</adapter>
                  <vlan>0</vlan>
                  <hardware_version>n/a</hardware_version>
                  <flows>
                    <items/>
                  </flows>
                  <ports>
                    <item>
                      <peers>
                        <item>
                          <port_no>1</port_no>
                          <device_id>simulated_onu_1</device_id>
                        </item>
                        <item>
                          <port_no>1</port_no>
                          <device_id>simulated_onu_2</device_id>
                        </item>
                      </peers>
                      <label>pon</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>PON_OLT</type>
                      <port_no>1</port_no>
                      <device_id>simulated_olt_1</device_id>
                    </item>
                    <item>
                      <peers/>
                      <label>eth</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>ETHERNET_NNI</type>
                      <port_no>2</port_no>
                      <device_id>simulated_olt_1</device_id>
                    </item>
                  </ports>
                  <parent_id/>
                  <oper_status>DISCOVERED</oper_status>
                  <flow_groups>
                    <items/>
                  </flow_groups>
                  <admin_state>UNKNOWN</admin_state>
                  <serial_number>19addcd7305d4d4fa90300cb8e4ab9a6</serial_number>
                  <model>n/a</model>
                  <root>True</root>
                  <id>simulated_olt_1</id>
                  <firmware_version>n/a</firmware_version>
                </item>
                <item>
                  <vendor>simulated</vendor>
                  <parent_port_no>1</parent_port_no>
                  <software_version>1.0</software_version>
                  <connect_status>UNKNOWN</connect_status>
                  <root>False</root>
                  <adapter>simulated_onu</adapter>
                  <vlan>101</vlan>
                  <hardware_version>n/a</hardware_version>
                  <flows>
                    <items/>
                  </flows>
                  <ports>
                    <item>
                      <peers/>
                      <label>eth</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>ETHERNET_UNI</type>
                      <port_no>2</port_no>
                      <device_id>simulated_onu_1</device_id>
                    </item>
                    <item>
                      <peers>
                        <item>
                          <port_no>1</port_no>
                          <device_id>simulated_olt_1</device_id>
                        </item>
                      </peers>
                      <label>pon</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>PON_ONU</type>
                      <port_no>1</port_no>
                      <device_id>simulated_onu_1</device_id>
                    </item>
                  </ports>
                  <parent_id>simulated_olt_1</parent_id>
                  <oper_status>DISCOVERED</oper_status>
                  <flow_groups>
                    <items/>
                  </flow_groups>
                  <admin_state>UNKNOWN</admin_state>
                  <serial_number>8ce6514e1b324d349038d9a80af04772</serial_number>
                  <model>n/a</model>
                  <type>simulated_onu</type>
                  <id>simulated_onu_1</id>
                  <firmware_version>n/a</firmware_version>
                </item>
                <item>
                  <vendor>simulated</vendor>
                  <parent_port_no>1</parent_port_no>
                  <software_version>1.0</software_version>
                  <connect_status>UNKNOWN</connect_status>
                  <root>False</root>
                  <adapter>simulated_onu</adapter>
                  <vlan>102</vlan>
                  <hardware_version>n/a</hardware_version>
                  <flows>
                    <items/>
                  </flows>
                  <ports>
                    <item>
                      <peers/>
                      <label>eth</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>ETHERNET_UNI</type>
                      <port_no>2</port_no>
                      <device_id>simulated_onu_2</device_id>
                    </item>
                    <item>
                      <peers>
                        <item>
                          <port_no>1</port_no>
                          <device_id>simulated_olt_1</device_id>
                        </item>
                      </peers>
                      <label>pon</label>
                      <oper_status>UNKNOWN</oper_status>
                      <admin_state>UNKNOWN</admin_state>
                      <type>PON_ONU</type>
                      <port_no>1</port_no>
                      <device_id>simulated_onu_2</device_id>
                    </item>
                  </ports>
                  <parent_id>simulated_olt_1</parent_id>
                  <oper_status>DISCOVERED</oper_status>
                  <flow_groups>
                    <items/>
                  </flow_groups>
                  <admin_state>UNKNOWN</admin_state>
                  <serial_number>0dfbb5af422044639c0660b518c06519</serial_number>
                  <model>n/a</model>
                  <type>simulated_onu</type>
                  <id>simulated_onu_2</id>
                  <firmware_version>n/a</firmware_version>
                </item>
              </devices>
              <instance_id>compose_voltha_1</instance_id>
              <version>0.9.0</version>
              <health>
                <state>HEALTHY</state>
              </health>
              <device_groups>
                <item>
                  <logical_devices/>
                  <id>1</id>
                  <devices/>
                </item>
              </device_groups>
              <adapters>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Voltha project</vendor>
                  <id>simulated_onu</id>
                  <logical_device_ids/>
                </item>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Tibit Communications Inc.</vendor>
                  <id>tibit_onu</id>
                  <logical_device_ids/>
                </item>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Voltha project</vendor>
                  <id>maple_olt</id>
                  <logical_device_ids/>
                </item>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Tibit Communications Inc.</vendor>
                  <id>tibit_olt</id>
                  <logical_device_ids/>
                </item>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Voltha project</vendor>
                  <id>broadcom_onu</id>
                  <logical_device_ids/>
                </item>
                <item>
                  <config>
                    <log_level>INFO</log_level>
                  </config>
                  <version>0.1</version>
                  <vendor>Voltha project</vendor>
                  <id>simulated_olt</id>
                  <logical_device_ids/>
                </item>
              </adapters>
             </instances>
             </Voltha>
            </data>
        """
        return etree.fromstring(xml_string)