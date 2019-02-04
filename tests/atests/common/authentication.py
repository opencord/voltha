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
vOLT-HA Authentication Test Case module
"""

import time
import os
import subprocess
import testCaseUtils
import logging


class Authentication(object):

    """
    This class implements voltha authentication test case
    """
    AUTHENTICATE_FILENAME = 'voltha_authenticate.log'
    
    def __init__(self):
        self.dirs = dict()
        self.dirs['log'] = None
        self.dirs['root'] = None
        self.dirs['voltha'] = None
        
        self.__rgName = None
        self.__radiusName = None
        self.__radiusIp = None
        
    def a_set_log_dirs(self, root_dir, voltha_dir, log_dir):
        testCaseUtils.config_dirs(self, log_dir, root_dir, voltha_dir)

    def discover_rg_pod_name(self):
        self.__rgName = testCaseUtils.extract_pod_name('rg-').strip()
         
    def discover_freeradius_pod_name(self):
        self.__radiusName = testCaseUtils.extract_pod_name('freeradius').strip()
        logging.info('freeradius Name = %s' % self.__radiusName)
        
    def discover_freeradius_ip_addr(self):
        ipAddr = testCaseUtils.extract_radius_ip_addr(self.__radiusName)
        assert ipAddr, 'No IP address listed for freeradius'
        self.__radiusIp = ipAddr.strip()
        logging.info('freeradius IP = %s' % self.__radiusIp)
        
    def set_current_freeradius_ip_in_aaa_json(self):
        status = testCaseUtils.modify_radius_ip_in_json_using_sed(self, self.__radiusIp)
        assert (status == 0), 'Setting Radius Ip in Json File did not return Success'
          
    def alter_aaa_application_configuration_in_onos_using_aaa_json(self):
        logging.info('Altering the Onos NetCfg AAA apps with Freeradius IP address')
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/aaa_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/aaa_json'
                  % testCaseUtils.get_dir(self, 'voltha'))
     
    def execute_authentication_on_rg(self):
        logging.info('Running Radius Authentication from RG')
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.AUTHENTICATE_FILENAME), 'w')
        proc1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'bash', '-c',
                                  '/sbin/wpa_supplicant -Dwired -ieth0 -c /etc/wpa_supplicant/wpa_supplicant.conf'],
                                 stdout=process_output,
                                 stderr=process_output)

        time.sleep(15)
        logging.debug('return value from supplicant subprocess = %s' % proc1.returncode)
        procPidSupplicant1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'ps', '-ef'],
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
        procPidSupplicant2 = subprocess.Popen(['grep', '-e', '/sbin/wpa_supplicant'], stdin=procPidSupplicant1.stdout,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
        procPidSupplicant3 = subprocess.Popen(['awk', "{print $2}"], stdin=procPidSupplicant2.stdout,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)

        procPidSupplicant1.stdout.close()
        procPidSupplicant2.stdout.close()

        out, err = procPidSupplicant3.communicate()
        supplicantPid = out.strip()
        
        procKillSupplicant1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'kill', supplicantPid],
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
        out, err = procKillSupplicant1.communicate()
        assert not err, 'Killing Supplicant returned %s' % err

        procPidBash1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'ps', '-ef'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        procPidBash2 = subprocess.Popen(['grep', '-e', '/bin/bash'], stdin=procPidBash1.stdout,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        procPidBash3 = subprocess.Popen(['awk', "{print $2}"], stdin=procPidBash2.stdout,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        procPidBash1.stdout.close()
        procPidBash2.stdout.close()

        out, err = procPidBash3.communicate()
        bashPid = out.strip()
        
        procKillBash1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'kill', '-9', bashPid],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = procKillBash1.communicate()
        assert not err, 'Killing Bash returned %s' % err

        process_output.close()       

        testCaseUtils.print_log_file(self, self.AUTHENTICATE_FILENAME)
        
    def verify_authentication_should_have_started(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'CTRL-EVENT-EAP-STARTED', self.AUTHENTICATE_FILENAME)
        assert statusLines, 'Authentication was not started'
        
    def verify_authentication_should_have_completed(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'CTRL-EVENT-EAP-SUCCESS', self.AUTHENTICATE_FILENAME)
        assert statusLines, 'Authentication was not completed successfully'

    def verify_authentication_should_have_disconnected(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'CTRL-EVENT-DISCONNECTED', self.AUTHENTICATE_FILENAME)
        assert statusLines, 'Authentication was not disconnected'

    def verify_authentication_should_have_terminated(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'CTRL-EVENT-TERMINATING', self.AUTHENTICATE_FILENAME)
        assert statusLines, 'Authentication was not terminated'
       

def run_test(root_dir, voltha_dir, log_dir):
    auth = Authentication()
    auth.a_set_log_dirs(root_dir, voltha_dir, log_dir)
    auth.discover_rg_pod_name()
    auth.discover_freeradius_pod_name()
    auth.discover_freeradius_ip_addr()
    auth.set_current_freeradius_ip_in_aaa_json()
    auth.alter_aaa_application_configuration_in_onos_using_aaa_json()
    auth.execute_authentication_on_rg()
    auth.verify_authentication_should_have_started()
    auth.verify_authentication_should_have_completed()
    auth.verify_authentication_should_have_disconnected()
    auth.verify_authentication_should_have_terminated()
