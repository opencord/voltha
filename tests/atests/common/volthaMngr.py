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
vOLT-HA Start/Stop module
"""


import os
import time
import subprocess
import paramiko
import spur

class volthaMngr(object):

    """
    This class implements voltha startup/shutdown callable helper functions
    """
    def __init__(self):
        self.__rootDir = None
        self.__volthaDir = None
        self.__logDir = None
        self.__rootSsh = None

    def configDir(self, rootDir, volthaDir, logDir):
        self.__rootDir = rootDir
        self.__volthaDir = volthaDir
        self.__logDir = logDir
        
        os.chdir(volthaDir)

    def openRootSsh(self):
        shell = spur.SshShell(hostname='localhost', username='root',
                              password='root',
                              missing_host_key=spur.ssh.MissingHostKey.accept)
        return shell

    def getAllRunningContainers(self):
        allContainers = []
        proc1 = subprocess.Popen(['docker', 'ps', '-a'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', '-v', 'CONT'], stdin=proc1.stdout,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        proc1.stdout.close
        out, err = proc2.communicate()
        if out:
            for line in out.split('\n'):
                items = line.split()
                if len(items):
                    allContainers.append(items)
        return allContainers

    def stopPonsim(self):
        command = "for pid in $(ps -ef | grep ponsim | grep -v grep | " \
                  "awk '{print $2}'); do echo $pid; done"
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('localhost', username='root', password='root')
        transport = client.get_transport()
        channel = transport.open_session()

        channel.exec_command(command)
        procIds = channel.recv(4096).replace('\n', ' ')
        channel = transport.open_session()
        channel.exec_command('sudo kill -9 %s' % procIds)

    def removeExistingContainers(self):
        allContainers = self.getAllRunningContainers()
        for container in allContainers:
            procID = container[0]
            os.system('docker rm -f %s > /dev/null 2>&1' % procID)

    def startVolthaContainers(self):
        print('Start VOLTHA containers')
        # Bring up all the containers required for VOLTHA (total 15)
        os.system(
            'docker-compose -f compose/docker-compose-system-test.yml '
            'up -d > %s/start_voltha_containers.log 2>&1' %
            self.__logDir)

    def collectAllLogs(self):
        print('Collect all VOLTHA container logs')
        allContainers = self.getAllRunningContainers()
        for container in allContainers:
            containerName = container[-1]
            os.system('docker logs --since 0m -f %s > %s/%s.log 2>&1 &' %
                      (containerName, self.__logDir, containerName))

    def enableBridge(self):
        self.__rootSsh = self.openRootSsh()
        result = self.__rootSsh.run([self.__rootDir + '/enable_bridge.sh'])
        print(result.output)

    def startPonsim(self, onusAmount=1):
        command = 'source env.sh ; ./ponsim/main.py -v'
        if onusAmount > 1:
            command += ' -o %s' % onusAmount
        ponsimLog = open('%s/ponsim.log' % self.__logDir, 'w')
        process = self.__rootSsh.spawn(['bash', '-c', command],
                                       cwd=self.__volthaDir, store_pid=True,
                                       stdout=ponsimLog)
        return process.pid


def voltha_Initialize(rootDir, volthaDir, logDir):

    voltha = volthaMngr()
    voltha.configDir(rootDir, volthaDir, logDir)
    voltha.stopPonsim()
    voltha.removeExistingContainers()
    voltha.startVolthaContainers()
    voltha.collectAllLogs()
    voltha.enableBridge()
    voltha.startPonsim(3)
    
