#!/usr/bin/env python
#
# Copyright 2017 the original author or authors.
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

"""
Alarm filter CLI commands
"""
from optparse import make_option, OptionValueError

from cmd2 import Cmd, options
from google.protobuf.empty_pb2 import Empty

from cli.table import print_pb_list_as_table
from voltha.protos import third_party
from voltha.protos import voltha_pb2
from voltha.protos.events_pb2 import AlarmEventType, AlarmEventSeverity, AlarmEventCategory

_ = third_party


class AlarmFiltersCli(Cmd):
    def __init__(self, get_stub):
        Cmd.__init__(self)
        self.get_stub = get_stub
        self.prompt = '(' + self.colorize(
            self.colorize('alarm_filters', 'red'), 'bold') + ') '

    def cmdloop(self):
        self._cmdloop()

    def help_show(self):
        self.poutput(
'''
Display the list of configured filters.

Valid options:

-i FILTER_ID | --filter-id=FILTER_ID                Display the filter rules for a specific filter id (OPTIONAL)

'''
        )

    @options([
        make_option('-i', '--filter-id', action="store", dest='filter_id')
    ])
    def do_show(self, line, opts):
        stub = self.get_stub()

        if not opts.filter_id:
            result = stub.ListAlarmFilters(Empty())
            print_pb_list_as_table("Alarm Filters:", result.filters, {}, self.poutput)
        else:
            result = stub.GetAlarmFilter(voltha_pb2.ID(id=opts.filter_id))
            print_pb_list_as_table("Rules for Filter ID = {}:".format(opts.filter_id),
                                   result.rules, {}, self.poutput)

    @staticmethod
    def construct_rule(raw_rule):
        rule = dict()

        rule_kv = raw_rule.strip().split(':')

        if len(rule_kv) == 2:
            rule['key'] = rule_kv[0].lower()
            rule['value'] = rule_kv[1].lower()
        else:
            raise OptionValueError("Error: A rule must be a colon separated key/value pair")

        return rule

    def parse_filter_rules(option, opt_str, value, parser):
        rules = getattr(parser.values, option.dest)
        if rules is None:
            rules = list()
            rules.append(AlarmFiltersCli.construct_rule(value))

            for arg in parser.rargs:
                if (arg[:2] == "--" and len(arg) > 2) or (arg[:1] == "-" and len(arg) > 1 and arg[1] != "-"):
                    break
                else:
                    rules.append(AlarmFiltersCli.construct_rule(arg))

            setattr(parser.values, option.dest, rules)
        else:
            raise OptionValueError('Warning: The filter rule option can only be specified once')

    def help_create(self):
        types = list(
            k for k, v in
            AlarmEventType.DESCRIPTOR.enum_values_by_name.items())
        categories = list(
            k for k, v in
            AlarmEventCategory.DESCRIPTOR.enum_values_by_name.items())
        severities = list(
            k for k, v in
            AlarmEventSeverity.DESCRIPTOR.enum_values_by_name.items())

        alarm_types = types
        alarm_categories = categories
        alarm_severities = severities

        usage = '''
Create a new alarm filter.

Valid options:

-r rule:value ... | --filter-rules rule:value ...   Specify one or more filter rules as key/value pairs (REQUIRED)

Valid rule keys and expected values:

id          : Identifier of an incoming alarm
type        : Type of an incoming alarm {}
category    : Category of an incoming alarm {}
severity    : Severity of an incoming alarm {}
resource_id : Resource identifier of an incoming alarm
device_id   : Device identifier of an incoming alarm

Example:

# Filter any alarm that matches the following criteria

create -r type:environment severity:indeterminate
create -r device_id:754f9dcbe4a6

'''.format(alarm_types, alarm_categories, alarm_severities)

        self.poutput(usage)

    @options([
        make_option('-r', '--filter-rules', help='<key>:<value>...', action="callback",
                    callback=parse_filter_rules, type='string', dest='filter_rules'),
    ])
    def do_create(self, line, opts):
        if opts.filter_rules:
            stub = self.get_stub()
            result = stub.CreateAlarmFilter(voltha_pb2.AlarmFilter(rules=opts.filter_rules))
            print_pb_list_as_table("Rules for Filter ID = {}:".format(result.id),
                                   result.rules, {}, self.poutput)

    def help_delete(self):
        self.poutput(
'''
Delete a specific alarm filter entry.

Valid options:

-i FILTER_ID | --filter-id=FILTER_ID                Display the filter rules for a specific filter id (REQUIRED)

'''
        )

    @options([
        make_option('-i', '--filter-id', action="store", dest='filter_id')
    ])
    def do_delete(self, line, opts):
        if not opts.filter_id:
            self.poutput(self.colorize('Error: ', 'red') + 'Specify ' + \
                         self.colorize(self.colorize('"filter id"', 'blue'),
                                       'bold') + ' to update')
            return

        stub = self.get_stub()
        stub.DeleteAlarmFilter(voltha_pb2.ID(id=opts.filter_id))

    def help_update(self):
        types = list(
            k for k, v in
            AlarmEventType.DESCRIPTOR.enum_values_by_name.items())
        categories = list(
            k for k, v in
            AlarmEventCategory.DESCRIPTOR.enum_values_by_name.items())
        severities = list(
            k for k, v in
            AlarmEventSeverity.DESCRIPTOR.enum_values_by_name.items())

        alarm_types = types
        alarm_categories = categories
        alarm_severities = severities

        usage = '''
Update the filter rules for an existing alarm filter.

Valid options:

-i FILTER_ID | --filter-id=FILTER_ID                Indicate the alarm filter identifier to update (REQUIRED)
-r rule:value ... | --filter-rules rule:value ...   Specify one or more filter rules as key/value pairs (REQUIRED)

Valid rule keys and expected values:

id          : Identifier of an incoming alarm
type        : Type of an incoming alarm {}
category    : Category of an incoming alarm {}
severity    : Severity of an incoming alarm {}
resource_id : Resource identifier of an incoming alarm
device_id   : Device identifier of an incoming alarm

Example:

# Filter any alarm that matches the following criteria

update -i 9da115b900bc -r type:environment severity:indeterminate resource_id:1554b0517a07

'''.format(alarm_types, alarm_categories, alarm_severities)

        self.poutput(usage)

    @options([
        make_option('-r', '--filter-rules', help='<key>:<value>...', action="callback",
                    callback=parse_filter_rules, type='string', dest='filter_rules'),
        make_option('-i', '--filter-id', action="store", dest='filter_id')
    ])
    def do_update(self, line, opts):
        if not opts.filter_id:
            self.poutput(self.colorize('Error: ', 'red') + 'Specify ' + \
                         self.colorize(self.colorize('"filter id"', 'blue'),
                                       'bold') + ' to update')
            return

        if opts.filter_rules:
            stub = self.get_stub()
            result = stub.UpdateAlarmFilter(
                voltha_pb2.AlarmFilter(id=opts.filter_id, rules=opts.filter_rules)
            )
            print_pb_list_as_table("Rules for Filter ID = {}:".format(result.id),
                                   result.rules, {}, self.poutput)
