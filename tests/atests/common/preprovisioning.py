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
vOLT-HA Pre-provisioning Test Case module
"""

import time
import testCaseUtils
import logging


class Preprovisioning(object):

    """
    This class implements voltha pre-provisioning test
    """
    
    def __init__(self):
        self.dirs = dict()
        self.dirs['log'] = None
        self.dirs['root'] = None
        self.dirs['voltha'] = None
        
        self.__oltIpAddress = None
        self.__oltPort = None
        self.__oltType = None
        self.__onuType = None
        self.__fields = []
        self.__oltDeviceId = None
        
    def p_set_log_dirs(self, log_dir):
        testCaseUtils.config_dirs(self, log_dir)

    def p_configure(self, olt_ip_address, olt_port, olt_type, onu_type):
        self.__oltIpAddress = olt_ip_address
        self.__oltPort = olt_port
        self.__oltType = olt_type
        self.__onuType = onu_type

    def preprovision_olt(self):
        logging.info('Do PROVISIONING')
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_preprovision_olt.log', 'preprovision_olt -t ponsim_olt -H %s:%s' %
                                                 (self.__oltIpAddress, self.__oltPort))
        time.sleep(5)
        
    def status_should_be_success_after_preprovision_command(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'success', 'voltha_preprovision_olt.log')
        assert statusLines, 'Preprovision Olt command should have returned success but did not'
        
    def query_devices_before_enabling(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_devices_before_enable.log', 'devices')
        testCaseUtils.print_log_file(self, 'voltha_devices_before_enable.log')
        time.sleep(5)
        
    def check_olt_fields_before_enabling(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltType, 'voltha_devices_before_enable.log')
        assert statusLines, 'No Olt listed under devices'
        self.__fields = testCaseUtils.parse_fields(statusLines)
        self.__oltDeviceId = self.__fields[1].strip()
        logging.debug("OLT device id = %s" % self.__oltDeviceId)
        adminState = self.__fields[3].strip()
        assert adminState == 'PREPROVISIONED', 'Admin State not PREPROVISIONED'
        hostPort = self.__fields[4].strip()
        assert hostPort, 'hostPort field is empty'
        hostPortFields = hostPort.split(":")
        assert hostPortFields[0].strip() == self.__oltIpAddress or hostPortFields[1] == str(self.__oltPort), \
            'Olt IP or Port does not match'
           
    def check_states(self, dev_type):
        result = True
        adminState = self.__fields[7].strip()
        assert adminState == 'ENABLED', 'Admin State of %s not ENABLED' % dev_type
        operatorStatus = self.__fields[8].strip()
        assert operatorStatus == 'ACTIVE', 'Operator Status of %s not ACTIVE' % dev_type
        connectStatus = self.__fields[9].strip()
        assert connectStatus == 'REACHABLE', 'Connect Status of %s not REACHABLE' % dev_type
        return result

    def check_olt_fields_after_enabling(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__oltType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Olt listed under devices'
        self.__fields = testCaseUtils.parse_fields(statusLines)
        assert self.check_states(self.__oltType), 'States of %s does match expected' % self.__oltType
        hostPort = self.__fields[11].strip()
        assert hostPort, 'hostPort field is empty'
        hostPortFields = hostPort.split(":")
        assert hostPortFields[0] == self.__oltIpAddress or hostPortFields[1] == str(self.__oltPort), \
            'Olt IP or Port does not match'
                      
    def check_onu_fields_after_enabling(self):        
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__onuType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Onu listed under devices'
        lines = statusLines.splitlines()
        lenLines = len(lines)
        assert lenLines == 1, 'Fixed single onu does not match, ONU Count was %d' % lenLines
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line)
            assert (self.check_states(self.__onuType) is True), 'States of %s does match expected' % self.__onuType
        
    def enable(self):
        logging.info('Enable %s OLT device' % self.__oltDeviceId)
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_enable.log', 'enable ' + self.__oltDeviceId)

    def status_should_be_success_after_enable_command(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'success', 'voltha_enable.log')
        assert statusLines, 'Enable command should have returned success but did not'
              
    def query_devices_after_enabling(self):
        testCaseUtils.send_command_to_voltha_cli(testCaseUtils.get_dir(self, 'log'),
                                                 'voltha_devices_after_enable.log', 'devices')
        testCaseUtils.print_log_file(self, 'voltha_devices_after_enable.log')


def run_test(olt_ip_address, olt_port, olt_type, onu_type, log_dir):
    preprovisioning = Preprovisioning()
    preprovisioning.p_set_log_dirs(log_dir)
    preprovisioning.p_configure(olt_ip_address, olt_port, olt_type, onu_type)
    preprovisioning.preprovision_olt()
    preprovisioning.status_should_be_success_after_preprovision_command()
    preprovisioning.query_devices_before_enabling()
    preprovisioning.check_olt_fields_before_enabling()
    preprovisioning.enable()
    preprovisioning.status_should_be_success_after_enable_command()
    preprovisioning.query_devices_after_enabling()
    preprovisioning.check_olt_fields_after_enabling()
    preprovisioning.check_onu_fields_after_enabling()
