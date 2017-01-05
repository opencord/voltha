#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
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

        # # Convert all remaining arguments to xml
        # for key, value in kwargs.items():
        #     key = key.replace('_', '-')
        #     etree.SubElement(rpcerr, "error-{}".format(key)).text = str(value)



class BadMsg(RPCError):
    def __init__(self, origmsg, exception=None):
        super(BadMsg, self).__init__(
                            origmsg,
                            Error.RPC,
                            Error.MALFORMED_MESSAGE,
                            info=str(exception))

    def get_xml_reply(self):
        return etree.tounicode(self.reply)


class InvalidValue(Error):
    def __init__(self, origmsg, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.INVALID_VALUE,
                          **kwargs)
    def get_xml_reply(self):
        return etree.tounicode(self.reply)



class MissingElement(RPCError):
    def __init__(self, origmsg, tag, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.MISSING_ELEMENT,
                          info=tag,
                          **kwargs)
    def get_xml_reply(self):
        return etree.tounicode(self.reply)



class BadElement(RPCError):
    def __init__(self, origmsg, element, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.BAD_ELEMENT,
                          info=element.tag,
                          **kwargs)

    def get_xml_reply(self):
        return etree.tounicode(self.reply)


class UnknownElement(RPCError):
    def __init__(self, origmsg, element, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.RPC,
                          Error.UNKNOWN_ELEMENT,
                          info=element.tag,
                          **kwargs)
    def get_xml_reply(self):
        return etree.tounicode(self.reply)


class NotImpl(RPCError):
    def __init__(self, origmsg, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.APPLICATION,
                          Error.OPERATION_NOT_SUPPORTED,
                          **kwargs)
    def get_xml_reply(self):
        return etree.tounicode(self.reply)



class ServerException(RPCError):
    def __init__(self, origmsg, exception, **kwargs):
        RPCError.__init__(self,
                          origmsg,
                          Error.APPLICATION,
                          Error.OPERATION_FAILED,
                          info=str(exception),
                          **kwargs)

    def get_xml_reply(self):
        return etree.tounicode(self.reply)

