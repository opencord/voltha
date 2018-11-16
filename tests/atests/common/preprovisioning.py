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
vOLT-HA Pre-provisioning Test module
"""

import time
import os
import commands
import testCaseUtils

class Preprovisioning(object):

    """
    This class implements voltha pre-provisioning test
    """
    
    def __init__(self):
        self.dirs = {}
        self.dirs ['log'] = None
        self.dirs ['root'] = None
        self.dirs ['voltha'] = None
        
        self.__oltIpAddress = None
        self.__oltPort = None
        self.__oltType = None
        self.__onuType = None
        self.__statusLines = ""
        self.__fields = []
        self.__oltDeviceId = None
        
    def pSetLogDirs(self, logDir):
        testCaseUtils.configDirs(self, logDir)

    def configure(self, oltIpAddress, oltPort, oltType, onuType):
        self.__oltIpAddress = oltIpAddress       
        self.__oltPort = oltPort
        self.__oltType = oltType
        self.__onuType = onuType

    def get_fields_from_grep_command(self, searchWord, logFile):
        grepCommand =\
            "grep %s %s/%s" % (searchWord, testCaseUtils.getDir(self, 'log'), logFile)  
        self.__statusLines = commands.getstatusoutput(grepCommand)[1]
        
    def preprovisionOlt(self):
        print('Do PROVISIONING')
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'),
            'preprovision_olt -t ponsim_olt -H %s:%s' %
            (self.__oltIpAddress, self.__oltPort),
            'voltha_preprovision_olt.log')
        time.sleep(5)
        
    def check_preprovision_success(self):
        self.get_fields_from_grep_command('success', 'voltha_preprovision_olt.log')
        if self.__statusLines:
            return True
        else:
            return False    
        
    def query_devices_before_enabling(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'devices',
                                        'voltha_devices_before_enable.log')
        time.sleep(5)
        
    def check_olt_fields_before_enabling(self):
        result = True
        self.get_fields_from_grep_command(self.__oltType, 'voltha_devices_before_enable.log')
        if self.__statusLines:
            self.__fields = testCaseUtils.parseFields(self.__statusLines)
            self.__oltDeviceId = self.__fields[1].strip()
            print ("OLT device id = %s" % self.__oltDeviceId)
            adminState = self.__fields[3].strip()
            if adminState != 'PREPROVISIONED':
                print ('Admin State not PREPROVISIONED')
                result = False
            hostPort = self.__fields[4].strip()
            if hostPort:
                hostPortFields = hostPort.split(":")
                if hostPortFields[0].strip() != self.__oltIpAddress or hostPortFields[1] != str(self.__oltPort):
                    print ('Olt IP or Port does not match')
                    result = False
            else:
                result = False
        else:
            print ('No Olt listed under devices')
            result = False
        return result        
           
    def check_states(self, devType):
        result = True
        adminState = self.__fields[7].strip()
        if adminState != 'ENABLED':
            print ('Admin State of %s not ENABLED' % devType)
            result = False
        operStatus = self.__fields[8].strip()
        if operStatus != 'ACTIVE':
            print ('Oper Status of %s not ACTIVE' % devType)
            result = False
        connectStatus = self.__fields[9].strip()
        if connectStatus != 'REACHABLE':
            print ('Connect Status of %s not REACHABLE' % devType)
            result = False
        return result    

    def check_olt_fields_after_enabling(self):
        result = True
        self.get_fields_from_grep_command(self.__oltType, 'voltha_devices_after_enable.log')
        if self.__statusLines:
            self.__fields = testCaseUtils.parseFields(self.__statusLines)
            if self.check_states(self.__oltType) != True:
                print ('States of %s does match expected' % self.__oltType)
                result = False
            hostPort = self.__fields[11].strip()
            if hostPort:
                hostPortFields = hostPort.split(":")
                if hostPortFields[0] != self.__oltIpAddress or hostPortFields[1] != str(self.__oltPort):
                    print ('Olt IP or Port does not match')
                    result = False
            else:
                result = False
        else:
            print ('No Olt listed under devices')
            result = False
        return result 
                     
    def check_onu_fields_after_enabling(self):        
        result = True
        self.get_fields_from_grep_command(self.__onuType, 'voltha_devices_after_enable.log')
        if self.__statusLines:
            lines = self.__statusLines.splitlines()
            lenLines = len(lines)
            if lenLines != 1: # Fixed number of onu for now
                print ('ONU Count was %d' % lenLines)
                result = False        
            for line in lines:
                self.__fields = testCaseUtils.parseFields(line)
                if self.check_states(self.__onuType) != True:
                    print ('States of %s does match expected' % self.__onuType)
                    result = False
        else:
            print ('No Onu listed under devices')
            result = False
        return result   
        
    def enable(self):
        print('Enable %s OLT device' % self.__oltDeviceId)
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'enable ' + self.__oltDeviceId,
                                        'voltha_enable.log')

    def check_enable_success(self):
        self.get_fields_from_grep_command('success', 'voltha_enable.log')
        if self.__statusLines:
            return True
        else:
            return False  
              
    def query_devices_after_enabling(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'devices',
                                        'voltha_devices_after_enable.log')

def runTest(oltIpAddress, oltPort, oltType, onuType, logDir):
    preprovisioning = Preprovisioning()
    preprovisioning.pSetLogDirs(logDir)
    preprovisioning.configure(oltIpAddress, oltPort, oltType, onuType)
    preprovisioning.preprovisionOlt()
    preprovisioning.check_preprovision_success()
    preprovisioning.query_devices_before_enabling()
    preprovisioning.check_olt_fields_before_enabling()
    preprovisioning.enable()
    preprovisioning.check_enable_success()
    preprovisioning.query_devices_after_enabling()
    preprovisioning.check_olt_fields_after_enabling()
    preprovisioning.check_onu_fields_after_enabling()
                                          
                                          

