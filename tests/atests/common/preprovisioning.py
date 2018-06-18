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


class PreprovisioningTest(object):

    def __init__(self, oltIpAddress, oltPort, logDir):
        self.__logDir = logDir

        print('Do PROVISIONING')
        self.send_command_to_voltha_cli(
            'preprovision_olt -t ponsim_olt -H %s:%d' %
            (oltIpAddress, oltPort),
            'voltha_preprovision_olt.log')
        time.sleep(5)
        self.send_command_to_voltha_cli('devices',
                                        'voltha_devices_before_enable.log')
        time.sleep(5)
        grepCommand =\
            "grep PREPROVISIONED %s/voltha_devices_before_enable.log | " \
            "awk '{print $2}'" % self.__logDir
        oltDeviceId = commands.getstatusoutput(grepCommand)[1].strip()

        print('Enable %s OLT device' % oltDeviceId)
        self.send_command_to_voltha_cli('enable ' + oltDeviceId,
                                        'voltha_enable.log')
        self.send_command_to_voltha_cli('devices',
                                        'voltha_devices_after_enable.log')

    def send_command_to_voltha_cli(self, cmd, logFile):
        # os.system("docker exec -i -t compose_cli_1 sh -c 'echo \"" + cmd +
        #           "\" > /voltha_tmp_command.txt'")
        os.system("docker exec compose_cli_1 sh -c 'echo \"" + cmd +
                  "\" > /voltha_tmp_command.txt'")
        os.system("docker exec compose_cli_1 sh -c '/cli/cli/main.py -C "
                  "vconsul:8500 -L < /voltha_tmp_command.txt' > " +
                  self.__logDir + '/' + logFile)

    def send_command_to_onos_cli(self, cmd, logFile):
        os.system(
            "sshpass -p karaf ssh -o StrictHostKeyChecking=no -p 8101 "
            "karaf@localhost " + cmd + " 2>/dev/null > " +
            self.__logDir + '/' + logFile)


def runTest(oltIpAddress, oltPort, logDir):
    preprovisioning = PreprovisioningTest(str(oltIpAddress), int(oltPort),
                                          str(logDir))
