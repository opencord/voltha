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
import structlog
from lxml import etree
import netconf.nc_common.error as ncerror

log = structlog.get_logger()


class RpcResponse():
    def __init__(self, capabilities):
        self.is_error = False
        # if there is an error then the reply_node will contains an Error
        # object
        self.reply_node = None
        self.close_session = False
        self.capabilities = capabilities
        self.custom_rpc = False

    def build_xml_response(self, request, voltha_response, custom_rpc=False):
        if request is None:
            return
        voltha_xml_string = etree.tostring(voltha_response)

        # Remove the leading and trailing <yang> tags
        if voltha_xml_string.startswith('<yang>'):
            voltha_xml_string = voltha_xml_string[len('<yang>'):]
            if voltha_xml_string.endswith('</yang>'):
                voltha_xml_string = voltha_xml_string[:-len('</yang>')]
        # Empty response
        elif voltha_xml_string.startswith('<yang/>'):
            voltha_xml_string = ''

        # Replace any True/False data to true/false
        voltha_xml_string = voltha_xml_string.replace('>False<', '>false<')
        voltha_xml_string = voltha_xml_string.replace('>True<', '>true<')

        if not custom_rpc:
            # Create the xml body as
            if request.has_key('subclass'):
                body = ''.join([
                    '<data>',
                    '<',
                    request['class'],
                    ' xmlns="',
                    request['namespace'],
                    '">',
                    '<',
                    request['subclass'],
                    '>',
                    voltha_xml_string,
                    '</',
                    request['subclass'],
                    '>',
                    '</',
                    request['class'],
                    '>',
                    '</data>'
                ])
            else:
                body = ''.join([
                    '<data>',
                    '<',
                    request['class'],
                    ' xmlns="urn:opencord:params:xml:ns:voltha:voltha">',
                    voltha_xml_string,
                    '</',
                    request['class'],
                    '>',
                    '</data>'
                ])
        else:  # custom_rpc
            body = ''.join([
                '<rpc-reply',
                ' xmlns="urn:opencord:params:xml:ns:voltha:voltha">',
                voltha_xml_string,
                '</rpc-reply>',
            ])

        return etree.fromstring(body)

    def add_node(self, new_node, tree):
        if new_node.tag == 'ignore':
            # We want only sub-elements
            for elem in list(new_node):
                tree.append(elem)
        else:
            tree.append(new_node)

    def copy_basic_element(self, elm):
        new_elem = etree.Element(elm.tag)
        new_elem.text = elm.text
        return new_elem

    def process_inline_option(self, elem):
        inline_option = False
        inline_node_name = None
        for elm in list(elem):
            if elm.tag == 'yang_field_option':
                inline_option = True
            if elm.tag == 'name':
                inline_node_name = elm.text
        if not inline_option:
            new_elem = etree.Element(elem.tag)
            return new_elem, elem

        # look for the node with the inline_node_name
        for elm in list(elem):
            if elm.tag == inline_node_name:
                new_elem = etree.Element('ignore')
                return new_elem, elm

    def process_element(self, elem):
        attrib = elem.get('type')
        if (attrib == 'list'):
            if list(elem) is None:
                return self.copy_basic_element(elem)
            new_elem = etree.Element('ignore')
            for elm in list(elem):
                elm.tag = elem.tag
                if elm.get('type') in ['list', 'dict']:
                    self.add_node(self.process_element(elm), new_elem)
                else:
                    new_elem.append(self.copy_basic_element(elm))
            return new_elem
        elif (attrib == 'dict'):
            # Empty case
            if list(elem) is None:
                return self.copy_basic_element(elem)

            # Process field option.
            new_elem, elem = self.process_inline_option(elem)

            for elm in list(elem):
                if elm.get('type') in ['list', 'dict']:
                    self.add_node(self.process_element(elm), new_elem)
                else:
                    new_elem.append(self.copy_basic_element(elm))
            return new_elem
        else:
            return self.copy_basic_element(elem)

    def to_yang_xml(self, from_xml, request, yang_options=None,
                    custom_rpc=False):
        # Parse from_xml as follows:
        # 1.  Any element having a list attribute shoud have each item move 1 level
        #     up and retag using the parent tag
        # 2.  Any element having a dict attribute and has a <yang_field_option>
        #     sub-element should have all it's items move to teh parent level
        top = etree.Element('yang')
        elms = list(from_xml)
        xml_tag = yang_options[0]
        list_items_name = yang_options[1]
        # Handle the special case when the the xml contains 1 element which
        # is a list type
        if len(elms) == 1:
            item = elms[0]
            if item.get('type') == 'list':
                if custom_rpc:  # custom rpc request
                    if list_items_name == 'items': # no pre-processing required
                        self.add_node(self.process_element(item), top)
                        return top
                    if xml_tag:
                        item.tag = xml_tag
                    else:
                        item.tag = 'ignore'
                else:
                    # Default netconf operations - may end up needing
                    # specific parsing per request type
                    if request.has_key('subclass'):
                        item.tag = request['subclass']
                        # remove the subclass element in request to avoid duplicate tag
                        del request['subclass']
                    elif list_items_name == 'items':
                        item.tag = xml_tag
                    else:
                        item.tag = 'ignore'
                self.add_node(self.process_element(item), top)
                return top

        # Process normally for all other cases
        for elm in elms:
            self.add_node(self.process_element(elm), top)

        return top

    # Helper method to sort the xml message based on the xml tags
    def sort_xml_response(self, xml):
        for parent in xml.xpath('//*[./*]'):  # Search for parent elements
            parent[:] = sorted(parent, key=lambda x: x.tag)
        return xml

    # custom_rpc refers to custom RPCs different from Netconf default RPCs
    # like get, get-config, edit-config, etc
    def build_yang_response(self, root, request, yang_options=None,
                            custom_rpc=False):
        try:
            self.custom_rpc = custom_rpc
            yang_xml = self.to_yang_xml(root, request, yang_options,
                                        custom_rpc)
            log.info('yang-xml', yang_xml=etree.tounicode(yang_xml,
                                                          pretty_print=True))
            return self.build_xml_response(request, yang_xml, custom_rpc)
        except Exception as e:
            log.exception('error-building-yang-response', request=request,
                          xml=etree.tostring(root))
            self.rpc_response.is_error = True
            self.rpc_response.node = ncerror.BadMsg(request)
            return
