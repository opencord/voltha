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

from chameleon.protoc_plugins.descriptor_parser import DescriptorParser
from chameleon.protoc_plugins.swagger_template \
    import native_descriptors_to_swagger, DuplicateMethodAndPathError, \
    ProtobufCompilationFailedError, InvalidPathArgumentError
from tests.utests.chameleon.protoc_plugins.test_utils import unindent, \
    json_rt, generate_plugin_request, load_file


class SwaggerTemplateTests(TestCase):

    maxDiff = 10000

    def gen_swagger(self, proto):
        request = generate_plugin_request(proto)
        parser = DescriptorParser()
        native_data = parser.parse_file_descriptors(request.proto_file,
                                                    type_tag_name='_type',
                                                    fold_comments=True)
        swagger = native_descriptors_to_swagger(native_data)
        return swagger

    def test_empty_def(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
        """)

        expected_swagger = {
            u'swagger': u'2.0',
            u'info': {
                u'title': u'test.proto',
                u'version': u'version not set'
            },
            u'schemes': [u"http", u"https"],
            u'consumes': [u"application/json"],
            u'produces': [u"application/json"],
            u'paths': {},
            u'definitions': {}
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger), expected_swagger)

    def test_empty_message_with_service(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {}
            service TestService {
              rpc Get(Null) returns(Null) {
                option (google.api.http) = {
                  get: "/test"
                };
              }
            }
        """)

        expected_swagger = {
            u'swagger': u'2.0',
            u'info': {
                u'title': u'test.proto',
                u'version': u"version not set"
            },
            u'schemes': [u"http", u"https"],
            u'consumes': [u"application/json"],
            u'produces': [u"application/json"],
            u'paths': {
                u'/test': {
                    u'get': {
                        u'operationId': u'Get',
                        u'responses': {
                            u'200': {
                                u'description': u'',
                                u'schema': {
                                    u'$ref': u'#/definitions/test.Null'
                                }
                            }
                        },
                        u'tags': [u'TestService']
                    }
                }
            },
            u'definitions': {
                u'test.Null': {
                    u'type': u'object'
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger), expected_swagger)

    def test_simple_annotated_message_with_simple_annotated_service(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";

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
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test"
                };
              }
            }
        """)

        expected_swagger = {
            u'swagger': u'2.0',
            u'info': {
                u'title': u'test.proto',
                u'version': u"version not set"
            },
            u'schemes': [u"http", u"https"],
            u'consumes': [u"application/json"],
            u'produces': [u"application/json"],
            u'paths': {
                u'/test': {
                    u'get': {
                        u'summary': u'Get simple answer',
                        u'description':
                            u' Returns the true answer to all of life\'s '
                            u'persistent questions.',
                        u'operationId': u'Get',
                        u'responses': {
                            u'200': {
                                u'description': u'',
                                u'schema': {
                                    u'$ref': u'#/definitions/test.Simple'
                                }
                            }
                        },
                        u'tags': [u'TestService']
                    }
                }
            },
            u'definitions': {
                u'test.Simple': {
                    u'description': u'Simple Message',
                    u'type': u'object',
                    u'properties': {
                        u'int': {
                            u'description': u'an int32 attribute',
                            u'type': u'integer',
                            u'format': u'int32'
                        },
                        u'str': {
                            u'description': u'a string attribute',
                            u'type': u'string',
                            u'format': u'string'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger), expected_swagger)

    def test_method_input_params_in_body(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";

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
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test"
                };
              }

              /*
               * Make up an answer (notice the leading blank line)
               *
               * Define the ultimate answer
               */
              rpc MakeUp(Simple) returns(Simple) {
                option (google.api.http) = {
                  post: "/test"
                  body: "*"
                };
              }
            }
        """)

        expected_swagger = {
            u'swagger': u'2.0',
            u'info': {
                u'title': u'test.proto',
                u'version': u"version not set"
            },
            u'schemes': [u"http", u"https"],
            u'consumes': [u"application/json"],
            u'produces': [u"application/json"],
            u'paths': {
                u'/test': {
                    u'get': {
                        u'summary': u'Get simple answer',
                        u'description':
                            u' Returns the true answer to all of life\'s '
                            u'persistent questions.',
                        u'operationId': u'Get',
                        u'responses': {
                            u'200': {
                                u'description': u'',
                                u'schema': {
                                    u'$ref': u'#/definitions/test.Simple'
                                }
                            }
                        },
                        u'tags': [u'TestService']
                    },
                    u'post': {
                        u'summary': u'Make up an answer (notice the leading '
                                    u'blank line)',
                        u'description': u' Define the ultimate answer',
                        u'operationId': u'MakeUp',
                        u'parameters': [{
                            u'name': u'body',
                            u'in': u'body',
                            u'required': True,
                            u'schema': {u'$ref': u'#/definitions/test.Simple'}
                        }],
                        u'responses': {
                            u'200': {
                                u'description': u'',
                                u'schema': {
                                    u'$ref': u'#/definitions/test.Simple'
                                }
                            }
                        },
                        u'tags': [u'TestService']
                    }
                }
            },
            u'definitions': {
                u'test.Simple': {
                    u'description': u'Simple Message',
                    u'type': u'object',
                    u'properties': {
                        u'int': {
                            u'description': u'an int32 attribute',
                            u'type': u'integer',
                            u'format': u'int32'
                        },
                        u'str': {
                            u'description': u'a string attribute',
                            u'type': u'string',
                            u'format': u'string'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger), expected_swagger)

    def test_catch_repeating_verbs_for_same_path(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {}
            service TestService {
              rpc Get(Null) returns(Null) {
                option (google.api.http) = {
                  get: "/test"
                };
              }
              rpc MakeUp(Null) returns(Null) {
                option (google.api.http) = {
                  get: "/test"
                  body: "*"
                };
              }
            }
        """)

        with self.assertRaises(DuplicateMethodAndPathError):
            self.gen_swagger(proto)

    def test_catch_unresolved_message_type_reference(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {}
            service TestService {
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test"
                };
              }
              rpc MakeUp(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test"
                  body: "*"
                };
              }
            }
        """)

        with self.assertRaises(ProtobufCompilationFailedError):
            self.gen_swagger(proto)

    def test_path_parameter_handling(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Simple {
                string str = 1;
                int32 int = 2;
            }
            service TestService {
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test/{str}/{int}"
                };
              }
            }
        """)

        expected_swagger_path = {
            u'/test/{str}/{int}': {
                u'get': {
                    u'operationId': u'Get',
                    u'parameters': [{
                        u'name': u'str',
                        u'in': u'path',
                        u'type': u'string',
                        u'format': u'string',
                        u'required': True
                    }, {
                        u'name': u'int',
                        u'in': u'path',
                        u'type': u'integer',
                        u'format': u'int32',
                        u'required': True
                    }],
                    u'responses': {
                        u'200': {
                            u'description': u'',
                            u'schema': {
                                u'$ref': u'#/definitions/test.Simple'
                            }
                        }
                    },
                    u'tags': [u'TestService']
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['paths']), expected_swagger_path)

    def test_path_parameter_error_handling(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Simple {
                string str = 1;
                int32 int = 2;
            }
            service TestService {
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/test/{str}/{xxxxx}/{int}"
                };
              }
            }
        """)

        with self.assertRaises(InvalidPathArgumentError):
            self.gen_swagger(proto)

    def test_alternative_bindings(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Simple {
                string str = 1;
                int32 int = 2;
            }
            service TestService {
              rpc Get(Simple) returns(Simple) {
                option (google.api.http) = {
                  get: "/v1/test/{str}/{int}"
                  additional_bindings {
                    post: "/v2/test"
                    body: "*"
                  }
                  additional_bindings {
                    get: "/v2/test/{int}/{str}"
                  }
                };
              }
            }
        """)

        expected_swagger_path = {
            u'/v1/test/{str}/{int}': {
                u'get': {
                    u'operationId': u'Get',
                    u'parameters': [{
                        u'name': u'str',
                        u'in': u'path',
                        u'type': u'string',
                        u'format': u'string',
                        u'required': True
                    }, {
                        u'name': u'int',
                        u'in': u'path',
                        u'type': u'integer',
                        u'format': u'int32',
                        u'required': True
                    }],
                    u'responses': {
                        u'200': {
                            u'description': u'',
                            u'schema': {
                                u'$ref': u'#/definitions/test.Simple'
                            }
                        }
                    },
                    u'tags': [u'TestService']
                }
            },
            u'/v2/test': {
                u'post': {
                    u'operationId': u'Get',
                    u'parameters': [{
                        u'in': u'body',
                        u'name': u'body',
                        u'required': True,
                        u'schema': {u'$ref': u'#/definitions/test.Simple'}
                    }],
                    u'responses': {
                        u'200': {
                            u'description': u'',
                            u'schema': {u'$ref': u'#/definitions/test.Simple'}
                        }
                    },
                    u'tags': [u'TestService']
                }
            },
            u'/v2/test/{int}/{str}': {
                u'get': {
                    u'operationId': u'Get',
                    u'parameters': [{
                        u'format': u'int32',
                        u'in': u'path',
                        u'name': u'int',
                        u'required': True,
                        u'type': u'integer'
                    }, {
                        u'format': u'string',
                        u'in': u'path',
                        u'name': u'str',
                        u'required': True,
                        u'type': u'string'
                    }],
                    u'responses': {
                        u'200': {
                            u'description': u'',
                            u'schema': {u'$ref': u'#/definitions/test.Simple'}
                        }
                    },
                    u'tags': [u'TestService']
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['paths']), expected_swagger_path)

    def test_google_null(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            import "google/protobuf/empty.proto";
            service TestService {
              rpc Get(google.protobuf.Empty) returns(google.protobuf.Empty) {
                option (google.api.http) = {
                  get: "/echo"
                };
              }
            }
        """)

        expected_swagger = {
            u'swagger': u'2.0',
            u'info': {
                u'title': u'test.proto',
                u'version': u"version not set"
            },
            u'schemes': [u"http", u"https"],
            u'consumes': [u"application/json"],
            u'produces': [u"application/json"],
            u'paths': {
                u'/echo': {
                    u'get': {
                        u'operationId': u'Get',
                        u'responses': {
                            u'200': {
                                u'description': u'',
                                u'schema': {
                                    u'$ref':
                                        u'#/definitions/google.protobuf.Empty'
                                }
                            }
                        },
                        u'tags': [u'TestService']
                    }
                }
            },
            u'definitions': {
                u'google.protobuf.Empty': {
                    u'description': u'A generic empty message that you can '
                                    u're-use to avoid defining duplicated\n '
                                    u'empty messages in your APIs. A typical '
                                    u'example is to use it as the request\n '
                                    u'or the response type of an API method. '
                                    u'For instance:\n\n     service Foo {\n  '
                                    u'     rpc Bar(google.protobuf.Empty) '
                                    u'returns (google.protobuf.Empty);\n     '
                                    u'}\n\n The JSON representation for '
                                    u'`Empty` is empty JSON object `{}`.',
                    u'type': u'object'
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger), expected_swagger)


    def test_nested_type_definitions(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            import "google/protobuf/empty.proto";
            message Null {}
            message Outer {
              message Inner {
                message Innermost {
                  bool healthy = 1;
                  string illness = 2;
                }
                Innermost innermost = 1;
                string other = 2;
              }
              string name = 1;
              Inner inner = 2;
            }
            service TestService {
              rpc Get(Null) returns(Outer) {
                option (google.api.http) = {
                  get: "/test"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.Outer': {
                u'type': u'object',
                u'properties': {
                    u'inner': {
                        u'$ref': u'#/definitions/test.Outer.Inner'
                    },
                    u'name': {
                        u'type': u'string',
                        u'format': u'string'
                    }
                }
            },
            u'test.Outer.Inner': {
                u'type': u'object',
                u'properties': {
                    u'innermost': {
                        u'$ref': u'#/definitions/test.Outer.Inner.Innermost'
                    },
                    u'other': {
                        u'type': u'string',
                        u'format': u'string'
                    }
                }
            },
            u'test.Outer.Inner.Innermost': {
                u'type': u'object',
                u'properties': {
                    u'healthy': {
                        u'type': u'boolean',
                        u'format': u'boolean'
                    },
                    u'illness': {
                        u'type': u'string',
                        u'format': u'string'
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_enum(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            // Detailed weather state
            enum WeatherState {
              GOOD = 0;  // Weather is good
              BAD = 1;  // Weather is bad
            }
            message Forecast {
              WeatherState forecast = 1;
            }
            service ForecastService {
              rpc GetForecast(Null) returns(Forecast) {
                option (google.api.http) = {
                  get: "/forecast"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.WeatherState': {
                u'default': u'GOOD',
                u'description': u'Detailed weather state\n'
                                u'Valid values:\n'
                                u' - GOOD: Weather is good\n'
                                u' - BAD: Weather is bad',
                u'type': u'string',
                u'enum': [u'GOOD', u'BAD']
            },
            u'test.Forecast': {
                u'type': u'object',
                u'properties': {
                    u'forecast': {u'$ref': u'#/definitions/test.WeatherState'}
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_nested_enum(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            message Forecast {
              // Detailed weather state
              enum WeatherState {
                GOOD = 0;  // Weather is good
                BAD = 1;  // Weather is bad
              }
              WeatherState forecast = 1;
            }
            service ForecastService {
              rpc GetForecast(Null) returns(Forecast) {
                option (google.api.http) = {
                  get: "/forecast"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.Forecast.WeatherState': {
                u'default': u'GOOD',
                u'description': u'Detailed weather state\n'
                                u'Valid values:\n'
                                u' - GOOD: Weather is good\n'
                                u' - BAD: Weather is bad',
                u'type': u'string',
                u'enum': [u'GOOD', u'BAD']
            },
            u'test.Forecast': {
                u'type': u'object',
                u'properties': {
                    u'forecast': {
                        u'$ref': u'#/definitions/test.Forecast.WeatherState'}
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_array_of_simple_types(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            message Invitations {
              string event = 1;
              repeated string names = 2;
              repeated int32 ages = 3;
            }
            service RsvpService {
              rpc Get(Null) returns(Invitations) {
                option (google.api.http) = {
                  get: "/invitations"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.Invitations': {
                u'type': u'object',
                u'properties': {
                    u'event': {
                        u'type': u'string',
                        u'format': u'string'
                    },
                    u'names': {
                        u'type': u'array',
                        u'items': {
                            u'type': u'string',
                            u'format': u'string'
                        }
                    },
                    u'ages': {
                        u'type': u'array',
                        u'items': {
                            u'type': u'integer',
                            u'format': u'int32'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_array_of_object_type(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            message Invitations {
              message Address {
                string street = 1;
                string city = 2;
              }
              string event = 1;
              repeated Null nulles = 2;
              repeated Address addresses = 3;
            }
            service RsvpService {
              rpc Get(Null) returns(Invitations) {
                option (google.api.http) = {
                  get: "/invitations"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.Invitations.Address': {
                u'type': u'object',
                u'properties': {
                    u'street': {
                        u'type': u'string',
                        u'format': u'string'
                    },
                    u'city': {
                        u'type': u'string',
                        u'format': u'string'
                    }
                }
            },
            u'test.Invitations': {
                u'type': u'object',
                u'properties': {
                    u'event': {
                        u'type': u'string',
                        u'format': u'string'
                    },
                    u'nulles': {
                        u'type': u'array',
                        u'items': {
                            u'$ref': u'#/definitions/test.Null'
                        }
                    },
                    u'addresses': {
                        u'type': u'array',
                        u'items': {
                            u'$ref': u'#/definitions/test.Invitations.Address'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_recursively_nested_values(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            message TreeNode {
              string name = 1;
              repeated TreeNode children = 2;
            }
            service RsvpService {
              rpc Get(Null) returns(TreeNode) {
                option (google.api.http) = {
                  get: "/invitations"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.TreeNode': {
                u'type': u'object',
                u'properties': {
                    u'name': {
                        u'type': u'string',
                        u'format': u'string'
                    },
                    u'children': {
                        u'type': u'array',
                        u'items': {
                            u'$ref': u'#/definitions/test.TreeNode'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_map_fields(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            message Maps {
              map<string, string> string_map = 1;
              map<string, int32> int32_map = 2;
              map<string, Null> object_map = 3;
            }
            service RsvpService {
              rpc Get(Null) returns(Maps) {
                option (google.api.http) = {
                  get: "/maps"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.Maps': {
                u'type': u'object',
                u'properties': {
                    u'string_map': {
                        u'type': u'object',
                        u'additionalProperties': {
                            u'type': u'string',
                            u'format': u'string'
                        }
                    },
                    u'int32_map': {
                        u'type': u'object',
                        u'additionalProperties': {
                            u'type': u'integer',
                            u'format': u'int32'
                        }
                    },
                    u'object_map': {
                        u'type': u'object',
                        u'additionalProperties': {
                            u'$ref': u'#/definitions/test.Null',
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_array_and_map_of_enum(self):

        proto = unindent("""
            syntax = "proto3";
            package test;
            import "google/api/annotations.proto";
            message Null {};
            enum State {
              GOOD = 0;
              BAD = 1;
            }
            message Map {
              map<string, State> enum_map = 1;
              repeated State states = 2;
            }
            service RsvpService {
              rpc Get(Null) returns(Map) {
                option (google.api.http) = {
                  get: "/maps"
                };
              }
            }
        """)

        expected_swagger_definitions = {
            u'test.Null': {u'type': u'object'},
            u'test.State': {
                u'default': u'GOOD',
                u'description': u'State\n'
                                u'Valid values:\n'
                                u' - GOOD\n'
                                u' - BAD',
                u'type': u'string',
                u'enum': [u'GOOD', u'BAD']
            },
            u'test.Map': {
                u'type': u'object',
                u'properties': {
                    u'enum_map': {
                        u'type': u'object',
                        u'additionalProperties': {
                            u'$ref': u'#/definitions/test.State',
                        }
                    },
                    u'states': {
                        u'type': u'array',
                        u'items': {
                            u'$ref': u'#/definitions/test.State'
                        }
                    }
                }
            }
        }

        swagger = self.gen_swagger(proto)
        self.assertEqual(json_rt(swagger['definitions']),
                         expected_swagger_definitions)

    def test_kitchen_sink(self):

        proto = load_file(
            os.path.dirname(__file__) + '/a_bit_of_everything.proto')

        swagger = self.gen_swagger(proto)

        expected_swagger = json.loads(load_file(
            os.path.dirname(__file__) + '/a_bit_of_everything.swagger.json')
        )

        self.maxDiff = 100000
        self.assertEqual(json_rt(swagger), expected_swagger)
