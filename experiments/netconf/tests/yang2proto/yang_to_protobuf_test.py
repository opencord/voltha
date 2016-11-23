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
from tests.utests.chameleon.protoc_plugins.test_utils import load_file


pyang_cmd = "pyang --plugindir /voltha/experiments/netconf/yang2proto -f " \
            "proto " \
            "-p /voltha/experiments/netconf/tests/yang2proto " \
            "/voltha/experiments/netconf/tests/yang2proto/{}"

class YangToProtoBufTests(TestCase):

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


    def test_01_basic_def(self):
        print "Test_01_basic_def_Start:------------------"
        t0 = time.time()

        # input file: /voltha/tests/utests/netconf/yang/basic.yang

        expected_response = """
            syntax = "proto3";
            package basic;

            message commonAttributes {
                uint32 my_id = 1 ;
                string my_name = 2 ;
                bool my_status = 3 ;
            }
            """

        try:
            cmd = pyang_cmd.format('basic.yang')
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            self._compare_file(response, expected_response)
        finally:
            print "Test_01_basic_def_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_02_container_def(self):
        print "Test_02_container_def_Start:------------------"
        t0 = time.time()

        # input file: /voltha/tests/utests/netconf/yang/container.yang

        expected_response = """
            syntax = "proto3";
            package container;

            message int_container {
                int32 eight = 1 ;
                int32 nine = 2 ;
            }
            """

        try:
            cmd = pyang_cmd.format('container.yang')
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            self._compare_file(response, expected_response)
        finally:
            print "Test_02_container_def_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_03_mix_simple_types(self):
        print "Test_03_mix_simple_types_Start:------------------"
        t0 = time.time()

        # input file: /voltha/tests/utests/netconf/yang/mix_simple_types.yang

        expected_response = """
            syntax = "proto3";
            package mix_simple_types;

            message user {
                string name = 1 ;
                string full_name = 2 ;
                string class = 3 ;
            }

            message int_container {
                int32 eight = 1 ;
                int32 nine = 2 ;
                int32 ten = 3 ;
            }
            message container1 {
                bool a = 1 ;
                Any b = 2 ;
                string mleaf = 3 ;
                repeated string mleaf_list = 4 ;
                message inner_container {
                    string mleaf1 = 1 ;
                    string mleaf2 = 2 ;
                }
            }
            """

        try:
            cmd = pyang_cmd.format('mix_simple_types.yang')
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            self._compare_file(response, expected_response)
        finally:
            print "Test_03_mix_simple_types_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_04_cord_tenant(self):
        print "Test_04_cord_tenant_Start:------------------"
        t0 = time.time()

        # input file: /voltha/tests/utests/netconf/yang/cord-tenant.yang

        expected_response = """
            syntax = "proto3";
            package cord_tenant;

            message subscriber {
                string label = 1 ;
                enum status
                {
                    violation = 0 ;
                    enabled = 1 ;
                    delinquent = 2 ;
                    suspended = 3 ;
                }
                bool demo = 3 ;
            }
            """
        try:
            cmd = pyang_cmd.format('cord-tenant.yang')
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            self._compare_file(response, expected_response)
        finally:
            print "Test_04_cord_tenant_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)


    def test_05_basic_rpc(self):
        print "Test_05_basic_rpc_Start:------------------"
        t0 = time.time()

        # input file: /voltha/tests/utests/netconf/yang/basic-rpc.yang

        expected_response = """
            syntax = "proto3";
            package basic_rpc;

            message my_id {
                uint32 my_id = 1 ;
            }
            message my_name {
                string my_name = 2 ;
            }
            message my_status {
                bool my_status = 3 ;
            }
            message my_input {
                string my_input = 4 ;
            }
            message my_output {
                string my_output = 5 ;
            }

            service basic_rpc {
                rpc do_something(my_input) returns(my_output) {}
            }
            """
        try:
            cmd = pyang_cmd.format('basic-rpc.yang')
            print 'running command: {}'.format(cmd)
            response, err, rc = run_command_to_completion_with_raw_stdout(cmd)
            self.assertEqual(rc, 0)

            self._compare_file(response, expected_response)
        finally:
            print "Test_05_basic_rpc_End:------------------ took {} " \
                  "secs\n\n".format(time.time() - t0)
