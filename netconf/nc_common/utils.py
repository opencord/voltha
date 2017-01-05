#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
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
from netconf.constants import Constants as C
from lxml import etree

ns_map = C.NS_MAP

def qmap(key):
    if ns_map.has_key(key):
        return ''.join(['{', ns_map[key], '}'])

def ns(key):
    if ns_map.has_key(key):
        return ns_map[key]

def qname(tag):
    try:
        return etree.QName(tag)
    except ValueError:
        prefix, base = tag.split(":")
        return etree.QName(ns(prefix), base)

def elm(tag, attrib=None, **extra):
    if attrib is None:
        attrib = dict()
    return etree.Element(qname(tag), attrib, **extra)

