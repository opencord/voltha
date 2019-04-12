#
# Copyright 2018 the original author or authors.
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
vOLT-HA Discovery Test Case module
"""

import testCaseUtils
import logging
import os


class Discovery(object):

    """
    This class implements voltha discovery test
    """
    
    def __init__(self):
        self.dirs = dict()
        self.dirs['log'] = None
        self.dirs['root'] = None
        self.dirs['voltha'] = None

        self.__logicalDeviceType = None
        self.__oltType = None
        self.__onuType = None
        self.__onuCount = None
        self.__fields = []
        self.__logicalDeviceId = None
        self.__oltDeviceId = None
        self.__onuDeviceIds = []
        self.__peers = None
        
    def d_set_log_dirs(self, log_dir):
        testCaseUtils.config_dirs(self, log_dir)

    def d_configure(self, logical_device_type, olt_type, onu_type, onu_count):
        self.__logicalDeviceType = logical_device_type
        self.__oltType = olt_type
        self.__onuType = onu_type
        self.__onuCount = onu_count

    def logical_device(self):
        logging.info('Logical Device Info')
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_logical_devices.log', 'logical_devices')
        testCaseUtils.print_log_file(self, 'voltha_logical_devices.log')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, '-i olt', 'voltha_logical_devices.log')
        assert statusLines, 'No Logical Device listed under logical devices'
        self.__fields = testCaseUtils.parse_fields(statusLines, '|')
        self.__logicalDeviceId = self.__fields[1].strip()
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_logical_device.log', 'logical_device ' + self.__logicalDeviceId,
                                                 'voltha_logical_device_ports.log', 'ports', 'voltha_logical_device_flows.log', 'flows')
        assert os.path.exists(testCaseUtils.get_dir(self, 'log') + '/voltha_logical_device.log') and \
            (os.path.getsize(testCaseUtils.get_dir(self, 'log') + '/voltha_logical_device.log') is 0), \
            'voltha_logical_device.log is not 0 length'
        testCaseUtils.print_log_file(self, 'voltha_logical_device_ports.log')
        testCaseUtils.print_log_file(self, 'voltha_logical_device_flows.log')

    def logical_device_ports_should_exist(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltDeviceId, 'voltha_logical_device_ports.log')
        assert statusLines, 'No Olt ports listed under logical device ports'
        self.__fields = testCaseUtils.parse_fields(statusLines, '|')
        portType = self.__fields[1].strip()
        assert portType.count('nni') == 1, 'Port type for %s does not match expected nni' % self.__oltDeviceId
        for onuDeviceId in self.__onuDeviceIds:
            statusLines = testCaseUtils.get_fields_from_grep_command(self, onuDeviceId, 'voltha_logical_device_ports.log')
            assert statusLines, 'No Onu device %s listed under logical device ports' % onuDeviceId
            self.__fields = testCaseUtils.parse_fields(statusLines, '|')
            portType = self.__fields[1].strip()
            assert portType.count('uni') == 1, 'Port type for %s does not match expected uni' % onuDeviceId

    def logical_device_should_have_at_least_one_flow(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Flows', 'voltha_logical_device_flows.log')
        assert statusLines, 'No Logical device flows listed for logical device'
        before, flows, numFlows = statusLines.partition('Flows')
        plainNumber = numFlows.strip().strip('():')
        if plainNumber.isdigit():
            assert int(plainNumber) > 0, 'Zero number of flows for logical device'

    def olt_discovery(self):
        logging.info('Olt Discovery')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Olt listed under devices'
        self.__fields = testCaseUtils.parse_fields(statusLines, '|')
        self.__oltDeviceId = self.__fields[1].strip()
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_olt_device.log', 'device ' + self.__oltDeviceId, 'voltha_olt_ports.log',
                                                 'ports', 'voltha_olt_flows.log', 'flows')
        testCaseUtils.print_log_file(self, 'voltha_olt_ports.log')
        testCaseUtils.print_log_file(self, 'voltha_olt_flows.log')
            
    def onu_discovery(self):
        logging.info('Onu Discovery')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__onuType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Onu listed under devices'
        lines = statusLines.splitlines()
        assert len(lines) == self.__onuCount, 'Onu count mismatch found: %s, should be: %s' % (len(lines), self.__onuCount)
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line, '|')
            onuDeviceId = self.__fields[1].strip()
            self.__onuDeviceIds.append(onuDeviceId)
            testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                     'voltha_onu_device_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log',
                                                     'device ' + onuDeviceId, 'voltha_onu_ports_' +
                                                     str(self.__onuDeviceIds.index(onuDeviceId)) + '.log', 'ports', 'voltha_onu_flows_' +
                                                     str(self.__onuDeviceIds.index(onuDeviceId)) + '.log', 'flows')
            testCaseUtils.print_log_file(self, 'voltha_onu_ports_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            testCaseUtils.print_log_file(self, 'voltha_onu_flows_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
                
    def olt_ports_should_be_enabled_and_active(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltDeviceId, 'voltha_olt_ports.log')
        assert statusLines, 'No Olt device listed under ports'
        lines = statusLines.splitlines()
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line, '|')
            assert (self.check_states(self.__oltDeviceId) is True), 'States of %s does match expected ' % self.__oltDeviceId
            portType = self.__fields[3].strip()
            assert (portType == 'ETHERNET_NNI' or portType == 'PON_OLT' or portType == 'ETHERNET_UNI'),\
                'Port type for %s does not match expected ETHERNET_NNI or PON_OLT' % self.__oltDeviceId
            if portType == 'PON_OLT':
                self.__peers = self.__fields[7].strip()
                peerFields = self.__peers.split(',')
                peerDevices = peerFields[1::2]
                for peerDevice in peerDevices:
                    deviceFields = peerDevice.split(':')
                    deviceId = deviceFields[1].replace("'", "").replace('u', '').rstrip("}]").strip()
                    assert deviceId in self.__onuDeviceIds, 'ONU Device %s not found as Peer' % deviceId
                    
    def onu_ports_should_be_enabled_and_active(self):
        for onuDeviceId in self.__onuDeviceIds:
            statusLines = testCaseUtils.get_fields_from_grep_command(self, onuDeviceId, 'voltha_onu_ports_' +
                                                                     str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            assert statusLines, 'No Onu device listed under ports'
            lines = statusLines.splitlines()
            for line in lines:
                self.__fields = testCaseUtils.parse_fields(line, '|')
                assert (self.check_states(onuDeviceId) is True), 'States of %s does match expected ' % onuDeviceId
                portType = self.__fields[3].strip()
                assert (portType == 'ETHERNET_UNI' or portType == 'PON_ONU'),\
                    'Port type for %s does not match expected ETHERNET_UNI or PON_ONU' % onuDeviceId
                if portType == 'PON_ONU':
                    self.__peers = self.__fields[7].strip()
                    peerFields = self.__peers.split(',')
                    peerDevice = peerFields[1]
                    deviceFields = peerDevice.split(':')
                    deviceId = deviceFields[1].replace("'", "").replace('u', '').rstrip("}]").strip()
                    assert deviceId == self.__oltDeviceId, 'OLT Device %s not found as Peer' % deviceId
                    
    def check_states(self, device_id):
        result = True
        stateMatchCount = 0
        for field in self.__fields:
            field_no_space = field.strip()
            if field_no_space == 'ENABLED' or field_no_space == 'ACTIVE':
                stateMatchCount += 1
        assert stateMatchCount == 2, 'State of %s is not ENABLED or ACTIVE' % device_id
        return result

    def olt_should_have_at_least_one_flow(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Flows', 'voltha_olt_flows.log')
        assert statusLines, 'No Olt flows under device %s' % self.__oltDeviceId
        before, flows, numFlows = statusLines.partition('Flows')
        plainNumber = numFlows.strip().strip('():')
        if plainNumber.isdigit():
            assert int(plainNumber) > 0, 'Zero number of flows for Olt %s' % self.__oltDeviceId
            
    def onu_should_have_at_least_one_flow(self):
        for onuDeviceId in self.__onuDeviceIds:
            statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Flows', 'voltha_onu_flows_' +
                                                                     str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            assert statusLines, 'No Onu flows under device %s' % onuDeviceId
            before, flows, numFlows = statusLines.partition('Flows')
            plainNumber = numFlows.strip().strip('():')
            if plainNumber.isdigit():
                assert int(plainNumber) > 0, 'Zero number of flows for Onu %s' % onuDeviceId
                      

def run_test(logical_device_type, olt_type, onu_type, onu_count, log_dir):
    discovery = Discovery()
    discovery.d_set_log_dirs(log_dir)
    discovery.d_configure(logical_device_type, olt_type, onu_type, onu_count)
    discovery.olt_discovery()
    discovery.onu_discovery()
    discovery.logical_device()
    discovery.logical_device_ports_should_exist()
    discovery.logical_device_should_have_at_least_one_flow()
    discovery.olt_ports_should_be_enabled_and_active()
    discovery.onu_ports_should_be_enabled_and_active()
    discovery.olt_should_have_at_least_one_flow()
    discovery.onu_should_have_at_least_one_flow()
