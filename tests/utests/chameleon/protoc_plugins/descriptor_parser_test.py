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
from unittest import TestCase

from chameleon.protoc_plugins.descriptor_parser import DescriptorParser
from tests.utests.chameleon.protoc_plugins.test_utils import \
    generate_plugin_request, json_rt
from tests.utests.chameleon.protoc_plugins.test_utils import unindent


class DescriptorParserTests(TestCase):

    maxDiff = 10000

    def test_empty(self):

        proto = unindent("""
        syntax = "proto3";
        package test;
        """)

        expected = dict(
            syntax='proto3',
            name='test.proto',
            package='test',
            source_code_info=dict(
                location=[
                    dict(span=[1, 0, 2, 13]),
                    dict(span=[1, 0, 18], path=[12]),
                    dict(span=[2, 8, 12], path=[2])
                ]
            )
        )

        request = generate_plugin_request(proto)
        assert len(request.proto_file) == 1
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptor(request.proto_file[0])
        self.assertEqual(native_data, expected)

    def test_message_with_comment_folding(self):

        proto = unindent("""
        syntax = "proto3";
        package test;

        // Sample message
        message SampleMessage {
          string name = 1; // inline comment

          // prefix comment
          repeated int32 number = 2;

          bool bool = 3;
          // suffix comment
        }
        """)

        expected = {
            u'syntax': u'proto3',
            u'name':  u'test.proto',
            u'package': u'test',
            u'message_type': [
                {
                    u'_description': u'Sample message',
                    u'name': u'SampleMessage',
                    u'field': [{
                        u'_description': u'inline comment',
                        u'json_name': u'name',
                        u'name': u'name',
                        u'label': 1,
                        u'number': 1,
                        u'type': 9
                    }, {
                        u'_description': u'prefix comment',
                        u'json_name': u'number',
                        u'name': u'number',
                        u'label': 3,
                        u'number': 2,
                        u'type': 5
                    }, {
                        u'_description': u'suffix comment',
                        u'json_name': u'bool',
                        u'name': u'bool',
                        u'label': 1,
                        u'number': 3,
                        u'type': 8
                    }],
                }
            ]
        }

        request = generate_plugin_request(proto)
        assert len(request.proto_file) == 1
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptor(request.proto_file[0],
                                                   fold_comments=True)
        self.assertEqual(json_rt(native_data), expected)

    def test_message_with_comment_folding_and_type_marking(self):

        proto = unindent("""
        syntax = "proto3";
        package test;

        // Sample message
        message SampleMessage {
          string name = 1; // inline comment

          // prefix comment
          repeated int32 number = 2;

          bool bool = 3;
          // suffix comment
        }
        """)

        expected = {
            u'syntax': u'proto3',
            u'name':  u'test.proto',
            u'package': u'test',
            u'_type': u'google.protobuf.FileDescriptorProto',
            u'message_type': [
                {
                    u'_type': u'google.protobuf.DescriptorProto',
                    u'_description': u'Sample message',
                    u'name': u'SampleMessage',
                    u'field': [{
                        u'_type': u'google.protobuf.FieldDescriptorProto',
                        u'_description': u'inline comment',
                        u'json_name': u'name',
                        u'name': u'name',
                        u'label': 1,
                        u'number': 1,
                        u'type': 9
                    }, {
                        u'_type': u'google.protobuf.FieldDescriptorProto',
                        u'_description': u'prefix comment',
                        u'json_name': u'number',
                        u'name': u'number',
                        u'label': 3,
                        u'number': 2,
                        u'type': 5
                    }, {
                        u'_type': u'google.protobuf.FieldDescriptorProto',
                        u'_description': u'suffix comment',
                        u'json_name': u'bool',
                        u'name': u'bool',
                        u'label': 1,
                        u'number': 3,
                        u'type': 8
                    }],
                }
            ]
        }

        request = generate_plugin_request(proto)
        assert len(request.proto_file) == 1
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptor(request.proto_file[0],
                                                   type_tag_name='_type',
                                                   fold_comments=True)
        self.assertEqual(json_rt(native_data), expected)

    def test_http_annotations_carry_over(self):

        proto = unindent("""
        syntax = "proto3";
        package test;
        import "google/api/annotations.proto";
        message Null {}
        service Test {
          rpc Call(Null) returns(Null) {
            option (google.api.http) = {
              get: "/some/path"
            };
          }
        }
        """)

        expected = {
            u'syntax': u'proto3',
            u'name': u'test.proto',
            u'package': u'test',
            u'dependency': [u'google/api/annotations.proto'],
            u'message_type': [{u'name': u'Null'}],
            u'service': [{
                u'name': u'Test',
                u'method': [{
                    u'name': u'Call',
                    u'input_type': u'.test.Null',
                    u'output_type': u'.test.Null',
                    u'options': {
                        u'http': {
                            u'get': u'/some/path'
                        }
                    }
                }]
            }]
        }

        request = generate_plugin_request(proto)
        assert len(request.proto_file) == 4
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptor(request.proto_file[3],
                                                   fold_comments=True)
        self.assertEqual(json_rt(native_data), expected)

    def test_http_annotations_carryover_and_all_components(self):

        proto = unindent("""
        syntax = "proto3";
        package test;
        import "google/api/annotations.proto";
        message Null {}
        service Test {
          rpc Call(Null) returns(Null) {
            option (google.api.http) = {
              get: "/some/path"
            };
          }
        }
        """)

        expected = {
            u'syntax': 'proto3',
            u'name': u'test.proto',
            u'package': u'test',
            u'dependency': [u'google/api/annotations.proto'],
            u'message_type': [{u'name': u'Null'}],
            u'service': [{
                u'name': u'Test',
                u'method': [{
                    u'name': u'Call',
                    u'input_type': u'.test.Null',
                    u'output_type': u'.test.Null',
                    u'options': {
                        u'http': {
                            u'get': u'/some/path'
                        }
                    }
                }]
            }]
        }

        request = generate_plugin_request(proto)
        assert len(request.proto_file) == 4
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptors(request.proto_file,
                                                    fold_comments=True)
        self.assertEqual([d['name'] for d in native_data], [
            u'google/api/http.proto',
            u'google/protobuf/descriptor.proto',
            u'google/api/annotations.proto',
            u'test.proto'
        ])
        self.assertEqual(json_rt(native_data[3]), expected)
