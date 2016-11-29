# -*- coding: utf-8 -*-#
#
# December 23 2014, Christian Hopps <chopps@gmail.com>
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
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
from lxml.etree import register_namespace

MAXSSHBUF = 16 * 1024
NSMAP = { }


def nsmap_add (prefix, namespace):
    "Add a prefix namespace mapping to the modules mapping dictionary"
    NSMAP[prefix] = namespace
    register_namespace(prefix, namespace)


def nsmap_update (nsdict):
    "Add a dicitonary of prefx namespace mappings to the modules mapping dictionary"
    NSMAP.update(nsdict)
    for key, val in nsdict.items():
        register_namespace(key, val)


def qmap (key):
    return "{" + NSMAP[key] + "}"


# Add base spec namespace
nsmap_add('nc', "urn:ietf:params:xml:ns:netconf:base:1.0")
