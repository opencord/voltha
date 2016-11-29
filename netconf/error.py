# -*- coding: utf-8 -*-#
#
# February 19 2015, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2015, Deutsche Telekom AG
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
#
from __future__ import absolute_import, division, unicode_literals, \
    print_function, nested_scopes
from lxml import etree
from netconf import NSMAP


class NetconfException(Exception):
    pass


class ChannelClosed(NetconfException):
    pass


class FramingError(NetconfException):
    pass


class SessionError(NetconfException):
    pass


class RPCError(NetconfException):
    def __init__(self, output, tree, error):
        super(RPCError, self).__init__(output)
        self.tree = tree
        self.error = error

    def _get_error_val(self, value):
        try:
            return self.error.xpath("nc:" + value, namespaces=NSMAP)[0].text
        except IndexError:
            return None

    def get_error_tag(self):
        return self._get_error_val("error-tag")

    def get_error_type(self):
        return self._get_error_val("error-type")

    def get_error_info(self):
        return self._get_error_val("error-info")

    def get_error_severity(self):
        return self._get_error_val("error-severity")


# RFC6241

# error-type
RPCERR_TYPE_TRANSPORT = 0
RPCERR_TYPE_RPC = 1
RPCERR_TYPE_PROTOCOL = 2
RPCERR_TYPE_APPLICATION = 3
RPCERR_TYPE_ENUM = {
    RPCERR_TYPE_TRANSPORT: "transport",
    RPCERR_TYPE_RPC: "rpc",
    RPCERR_TYPE_PROTOCOL: "protocol",
    RPCERR_TYPE_APPLICATION: "application"
}

# error-tag
RPCERR_TAG_IN_USE = "in-use"
RPCERR_TAG_INVALID_VALUE = "invalid-value"
RPCERR_TAG_TOO_BIG = "too-big"
RPCERR_TAG_MISSING_ATTRIBUTE = "missing-attribute"
RPCERR_TAG_BAD_ATTRIBUTE = "bad-attribute"
RPCERR_TAG_UNKNOWN_ATTRIBUTE = "unknown-attribute"
RPCERR_TAG_MISSING_ELEMENT = "missing-element"
RPCERR_TAG_BAD_ELEMENT = "bad-element"
RPCERR_TAG_UNKNOWN_ELEMENT = "unknown-element"
RPCERR_TAG_UNKNOWN_NAMESPACE = "unknown-namespace"
RPCERR_TAG_ACCESS_DENIED = "access-denied"
RPCERR_TAG_LOCK_DENIED = "lock-denied"
RPCERR_TAG_RESOURCE_DENIED = "resource-denied"
RPCERR_TAG_ROLLBACK_FAILED = "rollback-failed"
RPCERR_TAG_DATA_EXISTS = "data-exists"
RPCERR_TAG_DATA_MISSING = "data-missing"
RPCERR_TAG_OPERATION_NOT_SUPPORTED = "operation-not-supported"
RPCERR_TAG_OPERATION_FAILED = "operation-failed"
RPCERR_TAG_MALFORMED_MESSAGE = "malformed-message"


# error-app-tag
# error-path # xpath associated with error.
# error-message # human readable message describiing error
# error-info


class RPCServerError(NetconfException):
    def __init__(self, origmsg, etype, tag, **kwargs):
        # Add attrib and nsmap from original message.
        self.reply = etree.Element("rpc-reply", attrib=origmsg.attrib,
                                   nsmap=origmsg.nsmap)

        rpcerr = etree.SubElement(self.reply, "rpc-error")

        # We require a type, tag, and severity assuming error for severity.
        if etype in RPCERR_TYPE_ENUM:
            etype = RPCERR_TYPE_ENUM[etype]
        etree.SubElement(rpcerr, "error-type").text = str(etype)

        etree.SubElement(rpcerr, "error-tag").text = tag

        if "severity" not in kwargs:
            etree.SubElement(rpcerr, "error-severity").text = "error"

        # Now convert any other arguments to xml
        for key, value in kwargs.items():
            key = key.replace('_', '-')
            etree.SubElement(rpcerr, "error-{}".format(key)).text = str(value)

        # This sort of sucks for humans
        super(RPCServerError, self).__init__(self.get_reply_msg())

    def get_reply_msg(self):
        return etree.tounicode(self.reply)


class RPCSvrErrBadMsg(RPCServerError):
    """If the server raises this exception the and netconf 1.0 is in use, the session will be closed"""

    def __init__(self, origmsg):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC,
                                RPCERR_TAG_MALFORMED_MESSAGE)


class RPCSvrInvalidValue(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC,
                                RPCERR_TAG_INVALID_VALUE, **kwargs)


class RPCSvrMissingElement(RPCServerError):
    def __init__(self, origmsg, tag, **kwargs):
        try:
            # Old API had this as an element...
            tag = tag.tag
        except AttributeError:
            pass
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC,
                                RPCERR_TAG_MISSING_ELEMENT, info=tag, **kwargs)


class RPCSvrBadElement(RPCServerError):
    def __init__(self, origmsg, element, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC,
                                RPCERR_TAG_BAD_ELEMENT, info=element.tag,
                                **kwargs)


class RPCSvrUnknownElement(RPCServerError):
    def __init__(self, origmsg, element, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC,
                                RPCERR_TAG_UNKNOWN_ELEMENT, info=element.tag,
                                **kwargs)


class RPCSvrErrNotImpl(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL,
                                RPCERR_TAG_OPERATION_NOT_SUPPORTED, **kwargs)


class RPCSvrException(RPCServerError):
    def __init__(self, origmsg, exception, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL,
                                RPCERR_TAG_OPERATION_FAILED,
                                info=str(exception), **kwargs)


__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
