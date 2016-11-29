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
from __future__ import absolute_import, division, unicode_literals, \
    print_function, nested_scopes
import structlog
import io
from lxml import etree
from lxml.builder import E
import netconf.error as ncerror
from netconf import NSMAP, qmap
from utils import elm
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred

log = structlog.get_logger()

class NetconfProtocolError(Exception): pass


NC_BASE_10 = "urn:ietf:params:netconf:base:1.0"
NC_BASE_11 = "urn:ietf:params:netconf:base:1.1"
XML_HEADER = """<?xml version="1.0" encoding="utf-8"?>"""


class NetconfMethods(object):
    """This is an abstract class that is used to document the server methods functionality

    The server return not-implemented if the method is not found in the methods object,
    so feel free to use duck-typing here (i.e., no need to inherit)
    """

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        return

    def rpc_get(self, session, rpc, filter_or_none):  # pylint: disable=W0613
        """Passed the filter element or None if not present"""
        raise ncerror.RPCSvrErrNotImpl(rpc)

    def rpc_get_config(self, session, rpc, source_elm,
                       filter_or_none):  # pylint: disable=W0613
        """Passed the source element"""
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # TODO: The API WILL CHANGE consider unfinished
    def rpc_copy_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # TODO: The API WILL CHANGE consider unfinished
    def rpc_delete_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # TODO: The API WILL CHANGE consider unfinished
    def rpc_edit_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # TODO: The API WILL CHANGE consider unfinished
    def rpc_lock(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # TODO: The API WILL CHANGE consider unfinished
    def rpc_unlock(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)


class NetconfMethods(NetconfMethods):
    def rpc_get(self, unused_session, rpc, *unused_params):
        return etree.Element("ok")

    def rpc_get_config(self, unused_session, rpc, *unused_params):
        return etree.Element("ok")

    def rpc_namespaced(self, unused_session, rpc, *unused_params):
        return etree.Element("ok")


class NetconfProtocolHandler:
    def __init__(self, nc_server, nc_conn, grpc_stub):
        self.started = True
        self.conn = nc_conn
        self.nc_server = nc_server
        self.grpc_stub = grpc_stub
        self.methods = NetconfMethods()
        self.new_framing = False
        self.capabilities = set()
        self.session_id = 1
        self.session_open = False
        self.exiting = False
        self.connected = Deferred()
        self.connected.addCallback(self.nc_server.client_disconnected,
                                   self, None)

    def send_message(self, msg):
        self.conn.send_msg(XML_HEADER + msg, self.new_framing)

    def receive_message(self):
        return self.conn.receive_msg_any(self.new_framing)

    def allocate_session_id(self):
        sid = self.session_id
        self.session_id += 1
        return sid

    def send_hello(self, caplist, session_id=None):
        log.debug('starting', sessionId=session_id)
        msg = elm("hello", attrib={'xmlns': NSMAP['nc']})
        caps = E.capabilities(*[E.capability(x) for x in caplist])
        if session_id is not None:
            assert hasattr(self, "methods")
            self.methods.nc_append_capabilities(
                caps)  # pylint: disable=E1101
        msg.append(caps)

        if session_id is not None:
            msg.append(E("session-id", str(session_id)))
        msg = etree.tostring(msg)
        log.info("Sending HELLO", msg=msg)
        msg = msg.decode('utf-8')
        self.send_message(msg)

    def send_rpc_reply(self, rpc_reply, origmsg):
        reply = etree.Element(qmap('nc') + "rpc-reply", attrib=origmsg.attrib,
                              nsmap=origmsg.nsmap)
        try:
            rpc_reply.getchildren  # pylint: disable=W0104
            reply.append(rpc_reply)
        except AttributeError:
            reply.extend(rpc_reply)
        ucode = etree.tounicode(reply, pretty_print=True)
        log.debug("RPC-Reply", reply=ucode)
        self.send_message(ucode)

    @inlineCallbacks
    def open_session(self):
        # The transport should be connected at this point.
        try:
            # Send hello message.
            yield self.send_hello((NC_BASE_10, NC_BASE_11), self.session_id)

            # Get reply
            reply = yield self.receive_message()
            log.info("reply-received", reply=reply)

            # Parse reply
            tree = etree.parse(io.BytesIO(reply.encode('utf-8')))
            root = tree.getroot()
            caps = root.xpath("//nc:hello/nc:capabilities/nc:capability",
                              namespaces=NSMAP)

            # Store capabilities
            for cap in caps:
                self.capabilities.add(cap.text)

            if NC_BASE_11 in self.capabilities:
                self.new_framing = True
            elif NC_BASE_10 not in self.capabilities:
                raise SessionError(
                    "Server doesn't implement 1.0 or 1.1 of netconf")

            self.session_open = True

            log.info('session-opened', session_id=self.session_id,
                     framing="1.1" if self.new_framing else "1.0")

        except Exception as e:
            self.stop(repr(e))
            raise

    @inlineCallbacks
    def start(self):
        log.info('starting')

        try:
            yield self.open_session()
            while True:
                if not self.session_open:
                    break;

                msg = yield self.receive_message()
                self.handle_request(msg)
        except Exception as e:
            log.exception('exception', e=e)
            self.stop(repr(e))

        log.info('shutdown')
        returnValue(self)

    def handle_request(self, msg):
        if not self.session_open:
            return

        # Any error with XML encoding here is going to cause a session close
        # TODO: Return a malformed message.
        try:
            tree = etree.parse(io.BytesIO(msg.encode('utf-8')))
            if not tree:
                raise ncerror.SessionError(msg, "Invalid XML from client.")
        except etree.XMLSyntaxError:
            log.error("Closing-session-malformed-message", msg=msg)
            raise ncerror.SessionError(msg, "Invalid XML from client.")

        rpcs = tree.xpath("/nc:rpc", namespaces=NSMAP)
        if not rpcs:
            raise ncerror.SessionError(msg, "No rpc found")

        # A message can have multiple rpc requests
        for rpc in rpcs:
            try:
                msg_id = rpc.get('message-id')
                log.info("Received-rpc-message-id", msg_id=msg_id)
            except (TypeError, ValueError):
                raise ncerror.SessionError(msg,
                                           "No valid message-id attribute found")

            try:
                # Get the first child of rpc as the method name
                rpc_method = rpc.getchildren()
                if len(rpc_method) != 1:
                    log.error("badly-formatted-rpc-method", msg_id=msg_id)
                    raise ncerror.RPCSvrErrBadMsg(rpc)

                rpc_method = rpc_method[0]

                rpcname = rpc_method.tag.replace(qmap('nc'), "")
                params = rpc_method.getchildren()

                log.info("rpc-request", rpc=rpcname)

                handler = self.main_handlers.get(rpcname, None)
                if handler:
                    handler(self, rpcname, rpc, rpc_method, params)
                else:
                    log.error('cannot-handle',
                              request=msg, session_id=self.session_id,
                              rpc=rpc_method)

            except ncerror.RPCSvrErrBadMsg as msgerr:
                if self.new_framing:
                    self.send_message(msgerr.get_reply_msg())
                else:
                    # If we are 1.0 we have to simply close the connection
                    # as we are not allowed to send this error
                    log.error(
                        "Closing-1-0-session--malformed-message")
                    raise ncerror.SessionError(msg, "Malformed message")
            except ncerror.RPCServerError as error:
                self.send_message(error.get_reply_msg())
            except Exception as exception:
                error = ncerror.RPCSvrException(rpc, exception)
                self.send_message(error.get_reply_msg())

    @inlineCallbacks
    def handle_close_session_request(self, rpcname, rpc, rpc_method,
                                     params=None):
        log.info('closing-session')
        yield self.send_rpc_reply(etree.Element("ok"), rpc)
        self.close()

    @inlineCallbacks
    def handle_kill_session_request(self, rpcname, rpc, rpc_method,
                                    params=None):
        log.info('killing-session')
        yield self.send_rpc_reply(etree.Element("ok"), rpc)
        self.close()

    @inlineCallbacks
    def handle_get_request(self, rpcname, rpc, rpc_method, params=None):
        log.info('get')
        if len(params) > 1:
            raise ncerror.RPCSvrErrBadMsg(rpc)
        if params and not utils.filter_tag_match(params[0], "nc:filter"):
            raise ncerror.RPCSvrUnknownElement(rpc, params[0])
        if not params:
            params = [None]

        reply = yield self.invoke_method(rpcname, rpc, params)
        yield self.send_rpc_reply(reply, rpc)

    @inlineCallbacks
    def handle_get_config_request(self, rpcname, rpc, rpc_method, params=None):
        log.info('get-config')
        paramslen = len(params)
        # Verify that the source parameter is present
        if paramslen > 2:
            # TODO: need to specify all elements not known
            raise ncerror.RPCSvrErrBadMsg(rpc)
        source_param = rpc_method.find("nc:source", namespaces=NSMAP)
        if source_param is None:
            raise ncerror.RPCSvrMissingElement(rpc, utils.elm("nc:source"))
        filter_param = None
        if paramslen == 2:
            filter_param = rpc_method.find("nc:filter", namespaces=NSMAP)
            if filter_param is None:
                unknown_elm = params[0] if params[0] != source_param else \
                    params[1]
                raise ncerror.RPCSvrUnknownElement(rpc, unknown_elm)
        params = [source_param, filter_param]

        reply = yield self.invoke_method(rpcname, rpc, params)
        yield self.send_rpc_reply(reply, rpc)

    @inlineCallbacks
    def invoke_method(self, rpcname, rpc, params):
        try:
            # Handle any namespaces or prefixes in the tag, other than
            # "nc" which was removed above. Of course, this does not handle
            # namespace collisions, but that seems reasonable for now.
            rpcname = rpcname.rpartition("}")[-1]
            method_name = "rpc_" + rpcname.replace('-', '_')
            method = getattr(self.methods, method_name,
                             self._rpc_not_implemented)
            log.info("invoking-method", method=method_name)
            reply = yield method(self, rpc, *params)
            returnValue(reply)
        except NotImplementedError:
            raise ncerror.RPCSvrErrNotImpl(rpc)

    def stop(self, reason):
        if not self.exiting:
            log.debug('stopping')
            self.exiting = True
            if self.open_session:
                # TODO: send a closing message to the far end
                self.conn.close_connection()
            self.connected.callback(None)
            self.open_session = False
            log.info('stopped')

    def close(self):
        if not self.exiting:
            log.debug('closing-client')
            self.exiting = True
            if self.open_session:
                self.conn.close_connection()
            self.session_open = False
            self.connected.callback(None)
            self.open_session = False
            log.info('closing-client')

    main_handlers = {
        'get-config': handle_get_config_request,
        'get': handle_get_request,
        'kill-session': handle_kill_session_request,
        'close-session': handle_close_session_request
    }
