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
        self.__statusLine = ""
        self.__fields = []
        
    def pSetLogDirs(self, logDir):
        testCaseUtils.configDirs(self, logDir)

    def configure(self, oltIpAddress, oltPort):
        self.__oltIpAddress = oltIpAddress       
        self.__oltPort = oltPort

    def preprovisionOlt(self):
        print('Do PROVISIONING')
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'),
            'preprovision_olt -t ponsim_olt -H %s:%s' %
            (self.__oltIpAddress, self.__oltPort),
            'voltha_preprovision_olt.log')
        time.sleep(5)
   
    def query_devices_before_enable(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'devices',
                                        'voltha_devices_before_enable.log')
        time.sleep(5)
        grepCommand =\
            "grep PREPROVISIONED %s/voltha_devices_before_enable.log " % testCaseUtils.getDir(self, 'log')
        self.__statusLine = commands.getstatusoutput(grepCommand)[1]
        self.__fields = testCaseUtils.parseFields(self.__statusLine)
        self.__oltDeviceId = self.__fields[1].strip()
        print ("OLT device id = %s" % self.__oltDeviceId)
        
    def enable(self):
        print('Enable %s OLT device' % self.__oltDeviceId)
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'enable ' + self.__oltDeviceId,
                                        'voltha_enable.log')

    def query_devices_after_enable(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.getDir(self, 'log'), 'devices',
                                        'voltha_devices_after_enable.log')

def runTest(oltIpAddress, oltPort, logDir):
    preprovisioning = Preprovisioning()
    preprovisioning.pSetLogDirs(logDir)
    preprovisioning.configure(str(oltIpAddress), int(oltPort))
    preprovisioning.preprovisionOlt()
    preprovisioning.query_devices_before_enable()
    preprovisioning.enable()
    preprovisioning.query_devices_after_enable()
    
                                          
                                          

