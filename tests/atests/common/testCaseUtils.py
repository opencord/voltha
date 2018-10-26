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
vOLT-HA Test Case Utils module
"""
import time
import os
import commands
import subprocess
import pexpect
   
def configDirs(self, logDir, rootDir = None, volthaDir = None):
    self.dirs ['log'] = logDir
    self.dirs ['root'] = rootDir
    self.dirs ['voltha'] = volthaDir
    
def getDir(self, Dir):
    return self.dirs.get(Dir)
    
def removeLeadingLine(logDir, logFile):
    with open(logDir + '/' + logFile, 'r+') as file:
        lines = file.readlines()
        file.seek(0)
        lines = lines[1:]
        for line in lines:
            file.write(line)
        file.truncate()
        file.close()      

def send_command_to_voltha_cli(logDir, cmd, logFile):
    vcliIp = extractIpAddr('vcli')
    print (vcliIp)
    print (cmd)
    output = open(logDir + '/' + logFile, 'w')
    child = pexpect.spawn('ssh -p 5022 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no voltha@' + vcliIp)
    child.expect('[pP]assword:')
    child.sendline('admin')
    child.expect('\((\\x1b\[\d*;?\d+m){1,2}voltha(\\x1b\[\d*;?\d+m){1,2}\)')
    time.sleep(5)
    bytes = child.sendline(cmd)
    child.expect('\((\\x1b\[\d*;?\d+m){1,2}voltha(\\x1b\[\d*;?\d+m){1,2}\)')
    print (child.before)
    output.write(child.before)
    output.close()
    removeLeadingLine(logDir, logFile)
    child.close()

def send_command_to_onos_cli(logDir, cmd, logFile):
    onosIp = extractIpAddr('onos-ssh')
    print (onosIp)
    output = open(logDir + '/' + logFile, 'w')
    child = pexpect.spawn('ssh -p 8101 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no karaf@' + onosIp)
    
    child.expect('[pP]assword:')
    child.sendline('karaf')
    child.expect('(\\x1b\[\d*;?\d+m){1,2}onos>(\\x1b\[\d*;?\d+m){1,2}')
    child.sendline('flows')
    child.expect('flows')
    child.expect('(\\x1b\[\d*;?\d+m){1,2}onos>(\\x1b\[\d*;?\d+m){1,2}')

    output.write(child.before)
    
    output.close()
    child.close()

def parseFields(statusLine):
    statusList = statusLine.split("|")
    return statusList

def extractIpAddr(podName):
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'svc', '--all-namespaces'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-e', podName], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc3 = subprocess.Popen(['awk', "{print $4}"], stdin=proc2.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
                            
    proc1.stdout.close
    proc2.stdout.close
    out, err = proc3.communicate()
    return out
    
def extractPodName(shortPodName):
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'pods', '--all-namespaces'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-e', shortPodName], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc3 = subprocess.Popen(['awk', "{print $2}"], stdin=proc2.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
                      
                      
    proc1.stdout.close
    proc2.stdout.close
    out, err = proc3.communicate()
    return out

