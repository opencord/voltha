#!/usr/bin/env python
#
# Copyright 2016 the original author or authors.
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
from constants import Constants as C

class Capabilities:

    def __init__(self):
        self.server_caps = self._get_server_capabilities()
        self.client_caps = set()

    def add_client_capability(self, cap):
        self.client_caps.add(cap)

    #TODO:  This will be automatically generated from the voltha proto files
    def _get_server_capabilities(self):
        return (
            C.NETCONF_BASE_10,
            C.NETCONF_BASE_11,
            "urn:ietf:params:netconf:capability:writable-running:1.0",
            "urn:opencord:params:xml:ns:voltha:ietf-voltha",
            "urn:opencord:params:xml:ns:voltha:ietf-openflow_13",
            "urn:opencord:params:xml:ns:voltha:ietf-meta",
            "urn:opencord:params:xml:ns:voltha:ietf-logical_device",
            "urn:opencord:params:xml:ns:voltha:ietf-health",
            "urn:opencord:params:xml:ns:voltha:ietf-device",
            "urn:opencord:params:xml:ns:voltha:ietf-empty",
            "urn:opencord:params:xml:ns:voltha:ietf-common",
            "urn:opencord:params:xml:ns:voltha:ietf-any",
            "urn:opencord:params:xml:ns:voltha:ietf-adapter"
        )

    #TODO:  A schema exchange will also need to happen

    description = """

    Option 1:  Client already have the yang model for voltha and adapters:
        <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <capabilities>
                <capability>
                    urn:ietf:params:netconf:base:1.1
                </capability>
                <capability>
                    urn:cord:voltha:1.0
                </capability>
                <capability>
                    urn:cord:voltha:adpater_x:1.0
                </capability>


    Option 2: NETCONF-MONITORING - schema exchanges

        server expose capabilities

            <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <capabilities>
                    <capability>
                        urn:ietf:params:netconf:base:1.1
                    </capability>
                    <capability>
                        urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&revision=2010-10-04
                    </capability>

        client request schemas

            <rpc message-id="101"
                 xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
                <get>
                    <filter type="subtree">
                        <netconf-state xmlns=
                            "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                             <schemas/>
                        </netconf-state>
                    </filter>
                </get>
            </rpc>

        server sends back schemas

            <rpc-reply message-id="101"
                       xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
                  <data>
                        <netconf-state
                            xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                            <schemas>
                                <schema>
                                    <identifier>voltha</identifier>
                                    <version>1.0</version>
                                    <format>yang</format>
                                    <namespace>urn:cord:voltha</namespace>
                                    <location>NETCONF</location>
                                </schema>
                                <schema>
                                    <identifier>adapter_x</identifier>
                                    <version>x_release</version>
                                    <format>yang</format>
                                    <namespace>urn:cord:voltha:adapter_x</namespace>
                                    <location>NETCONF</location>
                                </schema>
                            </schemas>
                        </netconf-state>
                  </data>
            </rpc-reply>


        client requests each schema instance

            <rpc message-id="102"
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
                <get-schema
                    xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                    <identifer>voltha</identifer>
                    <version>1.0</version>
                </get-schema>
             </rpc>

             <rpc-reply message-id="102"
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <data
                    xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
                    module voltha {
                        //default format (yang) returned
                        //voltha version 0.1 yang module
                        //contents here ...
                    }
                </data>
             </rpc-reply>


    GETTING DATA

    Use filter:
        1) namespace filter
            <filter type="subtree">
                <top xmlns="http://example.com/schema/1.2/config"/>
            </filter>

         2) <filter type="subtree">
                <adapters xmlns="urn:cord:voltha:adapter_x">
                    <adapter>
                        <id>uuid</id>
                        <config/>
                    </adapter>
                </adapters>
            </filter>

            /voltha/adapters/<adapter>/[<id>, <vendor>, <version>, <config>, <additonal_desc>]

    """