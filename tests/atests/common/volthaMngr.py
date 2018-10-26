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
import testCaseUtils
import urlparse

class VolthaMngr(object):

    """
    This class implements voltha startup/shutdown callable helper functions
    """
    def __init__(self):
        self.dirs = {}
        self.dirs ['root'] = None
        self.dirs ['voltha'] = None
        self.dirs ['log'] = None
        
    def vSetLogDirs(self, rootDir, volthaDir, logDir):
        testCaseUtils.configDirs(self, logDir, rootDir, volthaDir)
        
    def startAllPods(self):
        proc1 = subprocess.Popen([testCaseUtils.getDir(self, 'root') + '/build.sh', 'start'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close

    def stopAllPods(self):
        proc1 = subprocess.Popen([testCaseUtils.getDir(self, 'root') + '/build.sh', 'stop'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close
        
    def resetKubeAdm(self):
        proc1 = subprocess.Popen([testCaseUtils.getDir(self, 'root') + '/build.sh', 'clear'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close

    """
    Because we are not deploying SEBA with XOS and NEM, and that a standalone Voltha
    deployment is not common, in order to get flows to work, we need to alter Onos 
    NetCfg in two fashion.
    One is to add to device list and the other is to add the missing Sadis section
    """        
    def alterOnosNetCfg(self):
        print ('Altering the Onos NetCfg to suit Voltha\'s needs')
        time.sleep(30)
        onosIp = testCaseUtils.extractIpAddr("onos-ui")
        netloc = onosIp.rstrip() + ":8181"
        devUrl = urlparse.urlunparse(('http', netloc, '/onos/v1/network/configuration/devices/', '', '', ''))
        sadisUrl = urlparse.urlunparse(('http', netloc, '/onos/v1/network/configuration/apps/', '', '', ''))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
            '%s -d @%s/tests/atests/build/devices_json' % (devUrl, testCaseUtils.getDir(self, 'voltha')))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
            '%s -d @%s/tests/atests/build/sadis_json' % (sadisUrl, testCaseUtils.getDir(self, 'voltha')))
            
    def getAllRunningPods(self):
        allRunningPods = []
        proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'pods', '--all-namespaces'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', '-v', 'NAMESPACE'], stdin=proc1.stdout,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        proc1.stdout.close
        out, err = proc2.communicate()
        print (out)
        if out:
            for line in out.split('\n'):
                items = line.split()
                nsName = {}
                if len(items) > 2:
                    nsName = {}
                    nsName['NS'] = items[0]
                    nsName['Name'] = items[1]
                    allRunningPods.append(nsName)
        return allRunningPods
 
    def collectPodLogs(self):
        print('Collect logs from all Pods')
        allRunningPods = self.getAllRunningPods()
        for nsName in allRunningPods:
            Namespace = nsName.get('NS')
            podName   = nsName.get('Name')
            os.system('/usr/bin/kubectl logs -n %s -f %s > %s/%s.log 2>&1 &' %
                      (Namespace, podName, testCaseUtils.getDir(self, 'log'), podName))

        
def voltha_Initialize(rootDir, volthaDir, logDir):
    voltha = VolthaMngr()
    voltha.vSetLogDirs(rootDir, volthaDir, logDir)
    voltha.stopAllPods()
    voltha.resetKubeAdm()
    voltha.startAllPods()
    voltha.alterOnosNetCfg()
    voltha.collectPodLogs()

