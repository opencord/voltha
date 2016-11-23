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
import json
import os
from unittest import TestCase
import time
from tests.itests.docutests.test_utils import run_command_to_completion_with_raw_stdout
from tests.utests.chameleon.protoc_plugins.test_utils import load_file, \
    unindent, save_file

proto_to_yang_cmd='python -m grpc.tools.protoc -I{}  ' \
                  '--plugin=protoc-gen-custom=/voltha/experiments' \
                  '/netconf/proto2yang/proto2yang.py --custom_out={} {}'

yang_validate_cmd="pyang -f tree --ietf {}"

TEMP_PATH="/tmp/proto2yang"
TEMP_INPUT_PROTO_FILE="test.proto"
TEMP_OUTPUT_YANG_FILE="ietf-test.yang"
TEMP_PROTO_PATH='{}/{}'.format(TEMP_PATH, TEMP_INPUT_PROTO_FILE)
TEMP_YANG_PATH='{}/{}'.format(TEMP_PATH, TEMP_OUTPUT_YANG_FILE)


class ProtoToYang(TestCase):

    def setup(self):
        if not os.path.exists(TEMP_PATH):
            os.makedirs(TEMP_PATH)


    def _compare_file(self, response, expected_response):
        # compare two files and strip empty lines, blanks, etc
        def _filter(x):
            x.strip()
            return x is not None

        response = filter(_filter,response.split())
        expected_response = filter(_filter,expected_response.split())
        print response
        print expected_response

        self.assertEqual(set(response), set(expected_response))

    def _gen_yang(self, proto):
        try:
            save_file(os.path.join(TEMP_PATH, TEMP_INPUT_PROTO_FILE), proto)
            cmd = proto_to_yang_cmd.format(TEMP_PATH, TEMP_PATH, TEMP_PROTO_PATH
                                           )
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            return load_file(TEMP_YANG_PATH)
        except Exception as e:
            print('Failure to generate yang file {}'.format(e))


    def test_01_empty_proto(self):
        print "Test_01_empty_proto_Start:------------------"
        t0 = time.time()

        proto = unindent("""
            syntax = "proto3";
            package test;
        """)

        expected_response = """
            module ietf-test {
                yang-version 1.1;
                namespace "urn:ietf:params:xml:ns:yang:ietf-test";
                prefix "voltha";

                organization "CORD";
                contact
                    " Any name";

                description
                    "";

                revision "2016-11-15" {
                    description "Initial revision.";
                    reference "reference";
                }
            }
            """

        try:
            yang = self._gen_yang(proto)
            self._compare_file(yang, expected_response)
        finally:
            print "Test_01_empty_proto_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_02_empty_message_with_service(self):
        print "Test_02_empty_message_with_service_Start:------------------"
        t0 = time.time()

        proto = unindent("""
            syntax = "proto3";
            package test;
            message Null {}
            service TestService {
              rpc Get(Null) returns(Null);
            }
        """)

        expected_response = """
            module ietf-test {
                yang-version 1.1;
                namespace "urn:ietf:params:xml:ns:yang:ietf-test";
                prefix "voltha";

                organization "CORD";
                contact
                    " Any name";

                description
                    "";

                revision "2016-11-15" {
                    description "Initial revision.";
                    reference "reference";
                }

                grouping Null {
                    description
                        "";
                }

                rpc TestService-Get {
                    description
                        "";
                    input {
                        uses Null;
                    }
                    output {
                        uses Null;
                    }
                }
            }
            """

        try:
            yang = self._gen_yang(proto)
            self._compare_file(yang, expected_response)
        finally:
            print "Test_02_empty_message_with_service_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_03_simple_message_with_service(self):
        print "Test__03_simple_message_with_service_Start:------------------"
        t0 = time.time()

        proto = unindent("""
            syntax = "proto3";
            package test;

            // Simple Message
            message Simple {
                string str = 1; // a string attribute
                int32 int = 2; // an int32 attribute
            }

            // Service to get things done
            service TestService {

              /* Get simple answer
               *
               * Returns the true answer to all of life's persistent questions.
               */
              rpc Get(Simple) returns(Simple);
            }
            """)

        expected_response = """
            module ietf-test {
                yang-version 1.1;
                namespace "urn:ietf:params:xml:ns:yang:ietf-test";
                prefix "voltha";

                organization "CORD";
                contact
                    " Any name";

                description
                    "";

                revision "2016-11-15" {
                    description "Initial revision.";
                    reference "reference";
                }


                grouping Simple {
                    description
                        "Simple Message";
                    leaf str {
                        type string;
                        description
                            "a string attribute";
                    }

                    leaf int {
                        type int32;
                        description
                            "an int32 attribute";
                    }

                }

                /*  Service to get things done" */
                rpc TestService-Get {
                    description
                        "Get simple answer

             Returns the true answer to all of life's persistent questions.";
                    input {
                        uses Simple;
                    }
                    output {
                        uses Simple;
                    }
                }
            }
            """

        try:
            yang = self._gen_yang(proto)
            self._compare_file(yang, expected_response)
        finally:
            print "Test_03_simple_message_with_service_End" \
                  ":------------------ took {} secs\n\n".format(time.time() - t0)


    def test_04_mix_types(self):
        print "Test__04_mix_types_Start:------------------"
        t0 = time.time()

        proto = unindent("""
            syntax = "proto3";

            package experiment;

            message AsyncEvent {
                int32 seq = 1;
                enum EventType {
                    BIG_BANG = 0;  // just a big bang
                    SMALL_BANG = 1;  // so small bang
                    NO_BANG = 2;
                }
                EventType type = 2;
                string details = 3;
            }

            enum SimpleEnum {
                APPLE = 0;
                BANANA = 1;
                ORANGE = 2;
            }

            message Packet {
                int32 source = 1;
                bytes content = 2;
                message InnerPacket {
                    string url = 1;
                    string title = 2;
                    repeated string snippets = 3;
                    message InnerInnerPacket {
                        string input = 1;
                        string desc = 2;
                    }
                    repeated InnerInnerPacket inner_inner_packet = 4;
                }
                repeated InnerPacket inner_packets = 3;
            }

            message Echo {
                string msg = 1;
                float delay = 2;
            }

            message testMessage{
                string test2 = 1;
                int32 test3 = 2;
            }

            service ExperimentalService {

                rpc GetEcho(Echo) returns(Echo);

                // For server to send async stream to client
                rpc ReceiveStreamedEvents(Packet)
                    returns(stream AsyncEvent);

                // For server to send async packets to client
                rpc ReceivePackets(Echo) returns(stream Packet);

                // For client to send async packets to server
                rpc SendPackets(stream Packet) returns(Echo);

            }
            """)

        expected_response = """
            module ietf-test {
                yang-version 1.1;
                namespace "urn:ietf:params:xml:ns:yang:ietf-test";
                prefix "voltha";

                organization "CORD";
                contact
                    " Any name";

                description
                    "";

                revision "2016-11-15" {
                    description "Initial revision.";
                    reference "reference";
                }

                typedef SimpleEnum {
                    type enumeration {
                        enum APPLE {
                            description "";
                        }
                        enum BANANA {
                            description "";
                        }
                        enum ORANGE {
                            description "";
                        }
                    }
                    description
                        "";
                }

                grouping AsyncEvent {
                    description
                        "";
                    leaf seq {
                        type int32;
                        description
                            "";
                    }

                    leaf type {
                        type EventType;
                        description
                            "";
                    }

                    leaf details {
                        type string;
                        description
                            "";
                    }

                    typedef EventType {
                        type enumeration {
                            enum BIG_BANG {
                                description "";
                            }
                            enum SMALL_BANG {
                                description "";
                            }
                            enum NO_BANG {
                                description "";
                            }
                        }
                        description
                            "";
                    }

                }

                grouping Packet {
                    description
                        "";
                    leaf source {
                        type int32;
                        description
                            "";
                    }

                    leaf content {
                        type binary;
                        description
                            "";
                    }

                    list inner_packets {
                        key "url";
                        uses InnerPacket;
                        description
                            "";
                    }

                    grouping InnerPacket {
                        description
                            "";
                        leaf url {
                            type string;
                            description
                                "";
                        }

                        leaf title {
                            type string;
                            description
                                "";
                        }

                        list snippets {
                            key "snippets";
                            leaf snippets {
                                type string;
                                description
                                    "";
                            }
                            description
                                "";
                        }

                        list inner_inner_packet {
                            key "input";
                            uses InnerInnerPacket;
                            description
                                "";
                        }

                        grouping InnerInnerPacket {
                            description
                                "";
                            leaf input {
                                type string;
                                description
                                    "";
                            }

                            leaf desc {
                                type string;
                                description
                                    "";
                            }

                        }

                    }

                }

                grouping Echo {
                    description
                        "";
                    leaf msg {
                        type string;
                        description
                            "";
                    }

                    leaf delay {
                        type decimal64 {
                           fraction-digits 5;
                        }
                        description
                            "";
                    }

                }

                container testMessage {
                    description
                        "";
                    leaf test2 {
                        type string;
                        description
                            "";
                    }

                    leaf test3 {
                        type int32;
                        description
                            "";
                    }

                }

                rpc ExperimentalService-GetEcho {
                    description
                        "";
                    input {
                        uses Echo;
                    }
                    output {
                        uses Echo;
                    }
                }

                rpc ExperimentalService-ReceiveStreamedEvents {
                    description
                        "For server to send async stream to client";
                    input {
                        uses Packet;
                    }
                    output {
                        uses AsyncEvent;
                    }
                }

                rpc ExperimentalService-ReceivePackets {
                    description
                        "For server to send async packets to client";
                    input {
                        uses Echo;
                    }
                    output {
                        uses Packet;
                    }
                }

                rpc ExperimentalService-SendPackets {
                    description
                        "For client to send async packets to server";
                    input {
                        uses Packet;
                    }
                    output {
                        uses Echo;
                    }
                }


            }
            """

        try:
            yang = self._gen_yang(proto)
            self._compare_file(yang, expected_response)
        finally:
            print "Test_04_mix_types_End" \
                  ":------------------ took {} secs\n\n".format(time.time() - t0)

