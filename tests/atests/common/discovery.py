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

import time
import os
import commands
import testCaseUtils
import logging

class Discovery(object):

    """
    This class implements voltha discovery test
    """
    
    def __init__(self):
        self.dirs = {}
        self.dirs ['log'] = None
        self.dirs ['root'] = None
        self.dirs ['voltha'] = None

        self.__logicalDeviceType = None
        self.__oltType = None
        self.__onuType = None
        self.__fields = []
        self.__logicalDeviceId = None
        self.__oltDeviceId = None
        self.__onuDeviceIds = []
        self.__peers = None
        
    def dSetLogDirs(self, logDir):
        testCaseUtils.configDirs(self, logDir)

    def dConfigure(self, logicalDeviceType, oltType, onuType):
        self.__logicalDeviceType = logicalDeviceType
        self.__oltType = oltType
        self.__onuType = onuType

    def logicalDevice(self):
        logging.info('Logical Device Info')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__logicalDeviceType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Logical Devices listed under devices'
        self.__fields = testCaseUtils.parseFields(statusLines)
        self.__logicalDeviceId = self.__fields[4].strip()
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'),
            'voltha_logical_device.log', 'logical_device ' + self.__logicalDeviceId, 'voltha_logical_device_ports.log', 'ports', 'voltha_logical_device_flows.log', 'flows')
        testCaseUtils.printLogFile (self, 'voltha_logical_device_ports.log')
        testCaseUtils.printLogFile (self, 'voltha_logical_device_flows.log')

    def oltDiscovery(self):
        logging.info('Olt Discovery')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Olt listed under devices'
        self.__fields = testCaseUtils.parseFields(statusLines)
        self.__oltDeviceId = self.__fields[1].strip()
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'),
            'voltha_olt_device.log', 'device ' + self.__oltDeviceId, 'voltha_olt_ports.log', 'ports', 'voltha_olt_flows.log', 'flows')
        testCaseUtils.printLogFile (self, 'voltha_olt_ports.log')
        testCaseUtils.printLogFile (self, 'voltha_olt_flows.log')
            
    def onuDiscovery(self):
        logging.info('Onu Discovery')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__onuType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Onu listed under devices'
        lines = statusLines.splitlines()
        for line in lines:
            self.__fields = testCaseUtils.parseFields(line)
            onuDeviceId = self.__fields[1].strip()
            self.__onuDeviceIds.append(onuDeviceId)
            testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'),
            'voltha_onu_device_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log', 'device ' + onuDeviceId, 
            'voltha_onu_ports_' +  str(self.__onuDeviceIds.index(onuDeviceId)) + '.log', 'ports', 
            'voltha_onu_flows_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log', 'flows')
            testCaseUtils.printLogFile (self, 'voltha_onu_ports_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            testCaseUtils.printLogFile (self, 'voltha_onu_flows_' + str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
                
    def olt_ports_should_be_enabled_and_active(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltDeviceId, 'voltha_olt_ports.log')
        assert statusLines, 'No Olt device listed under ports'
        lines = statusLines.splitlines()
        for line in lines:
            self.__fields = testCaseUtils.parseFields(line)
            assert self.check_states(self.__oltDeviceId) == True, 'States of %s does match expected ' % self.__oltDeviceId
            portType = self.__fields[3].strip()
            assert (portType == 'ETHERNET_NNI' or portType == 'PON_OLT'),\
            'Port type for %s does not match expected ETHERNET_NNI or PON_OLT' % self.__oltDeviceId
            if portType == 'PON_OLT':
                self.__peers = self.__fields[7].strip()
                peerFields = self.__peers.split(',')
                peerDevices = peerFields[1::2]
                for peerDevice in peerDevices:
                    deviceFields = peerDevice.split(':')
                    deviceId = deviceFields[1].replace("'","").replace('u','').rstrip("}]").strip()
                    assert deviceId in self.__onuDeviceIds, 'ONU Device %s not found as Peer' % deviceId
                    
    def onu_ports_should_be_enabled_and_active(self):
        for onuDeviceId in self.__onuDeviceIds:
            statusLines = testCaseUtils.get_fields_from_grep_command(self, onuDeviceId, 'voltha_onu_ports_' + \
            str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            assert statusLines, 'No Onu device listed under ports'
            lines = statusLines.splitlines()
            for line in lines:
                self.__fields = testCaseUtils.parseFields(line)
                assert self.check_states(onuDeviceId) == True, 'States of %s does match expected ' % onuDeviceId
                portType = self.__fields[3].strip()
                assert (portType == 'ETHERNET_UNI' or portType == 'PON_ONU'),\
                'Port type for %s does not match expected ETHERNET_UNI or PON_ONU' % onuDeviceId
                if portType == 'PON_ONU':
                    self.__peers = self.__fields[7].strip()
                    peerFields = self.__peers.split(',')
                    peerDevice = peerFields[1]
                    deviceFields = peerDevice.split(':')
                    deviceId = deviceFields[1].replace("'","").replace('u','').rstrip("}]").strip()
                    assert deviceId == self.__oltDeviceId, 'OLT Device %s not found as Peer' % deviceId
                    
                           
    def check_states(self, deviceId):
        result = True
        adminState = self.__fields[4].strip()
        assert adminState == 'ENABLED', 'Admin State of %s not ENABLED' % deviceId
        operStatus = self.__fields[5].strip()
        assert operStatus == 'ACTIVE', 'Oper Status of %s not ACTIVE' % deviceId
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
            statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Flows', 'voltha_onu_flows_' + \
            str(self.__onuDeviceIds.index(onuDeviceId)) + '.log')
            assert statusLines, 'No Onu flows under device %s' % onuDeviceId
            before, flows, numFlows = statusLines.partition('Flows')
            plainNumber = numFlows.strip().strip('():')
            if plainNumber.isdigit():
                assert int(plainNumber) > 0, 'Zero number of flows for Onu %s' % onuDeviceId
                      

def runTest(logicalDeviceType, oltType, onuType, logDir):
    discovery = Discovery()
    discovery.dSetLogDirs(logDir)
    discovery.dConfigure(logicalDeviceType, oltType, onuType)
    discovery.oltDiscovery()
    discovery.onuDiscovery()
    discovery.logicalDevice()
    discovery.olt_ports_should_be_enabled_and_active()                                      
    discovery.onu_ports_should_be_enabled_and_active()
    discovery.olt_should_have_at_least_one_flow()
    discovery.onu_should_have_at_least_one_flow()
