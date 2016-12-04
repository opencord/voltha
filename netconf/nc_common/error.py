#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
#
# Adapted from https://github.com/choppsv1/netconf/error.py
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
from netconf.constants import Constants as C
from lxml import etree

class Error(Exception):

    ###	Tag ###
    IN_USE = "in-use"
    INVALID_VALUE = "invalid-value"
    TOO_BIG = "too-big"
    MISSING_ATTRIBUTE = "missing-attribute"
    BAD_ATTRIBUTE = "bad-attribute"
    UNKNOWN_ATTRIBUTE = "unknown-attribute"
    MISSING_ELEMENT = "missing-element"
    BAD_ELEMENT = "bad-element"
    UNKNOWN_ELEMENT = "unknown-element"
    UNKNOWN_NAMESPACE = "unknown-namespace"
    ACCESS_DENIED = "access-denied"
    LOCK_DENIED = "lock-denied"
    RESOURCE_DENIED = "resource-denied"
    ROLLBACK_FAILED = "rollback-failed"
    DATA_EXISTS = "data-exists"
    DATA_MISSING = "data-missing"
    OPERATION_NOT_SUPPORTED = "operation-not-supported"
    OPERATION_FAILED = "operation-failed"
    MALFORMED_MESSAGE = "malformed-message"

    ###  Error-type ###
    TRANSPORT = 0
    RPC = 1
    PROTOCOL = 2
    APPLICATION = 3
    ERROR_TYPE_ENUM = {
        TRANSPORT: "transport",
        RPC: "rpc",
        PROTOCOL: "protocol",
        APPLICATION: "application"
    }

    ###  Severity  ###
    ERROR = "error"
    WARNING = "warning"

    ### Error-info ###
    BAD_ATTRIBUTE_INFO = "bad-attribute"
    BAD_ELEMENT_INFO = "bad-element"
    SESSION_ID_INFO = "session-id"
    OK_ELEMENT_INFO = "ok-element"
    ERR_ELEMENT_INFO = "err-element"
    NOOP_ELEMENT_INFO = "noop-element"

    ### XML Error tags ###
    XML_ERROR_TYPE = "error-type"
    XML_ERROR_TAG = "error-tag"
    XML_ERROR_SEV = "error-severity"


    # def __init__(self, replynode=None, error_type=None, error_tag=None,
    #              error_severity=None, error_tag_app=None, error_path=None,
    #              error_message=None):
    #
    #     self.replynode = replynode
    #     self.error_type = error_type
    #     self.error_tag = error_tag
    #     self.error_severity = error_severity
    #     self.error_tag_app = error_tag_app
    #     self.error_path = error_path
    #     self.error_message = error_message
    #     self.error_info = []

class ChannelClosed(Error):
    pass

class FramingError(Error):
    pass

class SessionError(Error):
    pass


class RPCError(Error):
    def __init__(self, origmsg, error_type, error_tag, **kwargs):
        # Create the rpc reply
        # Append original attributes and namespace
        self.reply = etree.Element(C.RPC_REPLY,
                                   attrib=origmsg.attrib,
                                   nsmap=origmsg.nsmap)

        rpcerr = etree.SubElement(self.reply, C.RPC_ERROR)

        if error_type in Error.ERROR_TYPE_ENUM:
            error_type = Error.ERROR_TYPE_ENUM[error_type]
        else:
            error_type = Error.ERROR_TYPE_ENUM[Error.RPC]

        etree.SubElement(rpcerr, Error.XML_ERROR_TYPE).text = str(error_type)

        etree.SubElement(rpcerr, Error.XML_ERROR_TAG).text = error_tag

        if "severity" not in kwargs:
            etree.SubElement(rpcerr, Error.XML_ERROR_SEV).text = "error"

        # Convert all remaining arguments to xml
        for key, value in kwargs.items():
            key = key.replace('_', '-')
            etree.SubElement(rpcerr, "error-{}".format(key)).text = str(value)

        # super(RPCError, self).__init__(self.get_xml_reply())

    def get_xml_reply(self):
        return etree.tounicode(self.reply)


class BadMsg(RPCError):
    def __init__(self, origmsg):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.MALFORMED_MESSAGE)


class InvalidValue(Error):
    def __init__(self, origmsg, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.INVALID_VALUE,
                          **kwargs)


class MissingElement(RPCError):
    def __init__(self, origmsg, tag, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.MISSING_ELEMENT,
                          info=tag,
                          **kwargs)


class BadElement(RPCError):
    def __init__(self, origmsg, element, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.BAD_ELEMENT,
                          info=element.tag,
                          **kwargs)


class UnknownElement(RPCError):
    def __init__(self, origmsg, element, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.UNKNOWN_ELEMENT,
                          info=element.tag,
                          **kwargs)


class NotImpl(RPCError):
    def __init__(self, origmsg, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.PROTOCOL,
                          Error.OPERATION_NOT_SUPPORTED,
                          **kwargs)


class ServerException(RPCError):
    def __init__(self, origmsg, exception, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.PROTOCOL,
                          Error.OPERATION_FAILED,
                          info=str(exception),
                          **kwargs)

