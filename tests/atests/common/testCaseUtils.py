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
import commands
import subprocess
import pexpect
import sys
   

def config_dirs(self, log_dir, root_dir=None, voltha_dir=None):
    self.dirs['log'] = log_dir
    self.dirs['root'] = root_dir
    self.dirs['voltha'] = voltha_dir
    

def get_dir(self, directory):
    return self.dirs.get(directory)
    

def remove_leading_line(log_dir, log_file):
    with open(log_dir + '/' + log_file, 'r+') as FILE:
        lines = FILE.readlines()
        FILE.seek(0)
        lines = lines[1:]
        for line in lines:
            FILE.write(line)
        FILE.truncate()
        FILE.close()


def send_command_to_voltha_cli(log_dir, log_file1, cmd1, log_file2=None, cmd2=None, log_file3=None, cmd3=None, host='localhost'):
    output = open(log_dir + '/' + log_file1, 'w')
    child = pexpect.spawn('ssh -p 30110 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no voltha@%s' % host)
    child.expect('[pP]assword:')
    child.sendline('admin')
    child.expect('\((\\x1b\[\d*;?\d+m){1,2}voltha(\\x1b\[\d*;?\d+m){1,2}\)')
    time.sleep(10)
    child.sendline(cmd1)
    i = child.expect(['\((\\x1b\[\d*;?\d+m){1,2}voltha(\\x1b\[\d*;?\d+m){1,2}\)',
                     '\((\\x1b\[\d*;?\d+m){1,2}.*device [0-9a-f]{16}(\\x1b\[\d*;?\d+m){1,2}\)'])
    if i == 0:
        output.write(child.before)
        output.close()
        remove_leading_line(log_dir, log_file1)
    elif i == 1:
        if log_file2 is not None and cmd2 is not None:
            output = open(log_dir + '/' + log_file2, 'w')
            child.sendline(cmd2)
            child.expect('\((\\x1b\[\d*;?\d+m){1,2}.*device [0-9a-f]{16}(\\x1b\[\d*;?\d+m){1,2}\)')
            output.write(child.before)
            output.close()
            remove_leading_line(log_dir, log_file2)
        if log_file3 is not None and cmd3 is not None:
            output = open(log_dir + '/' + log_file3, 'w')
            child.sendline(cmd3)
            child.expect('\((\\x1b\[\d*;?\d+m){1,2}.*device [0-9a-f]{16}(\\x1b\[\d*;?\d+m){1,2}\)')
            output.write(child.before)
            output.close()
            remove_leading_line(log_dir, log_file3)
    child.close()


def send_command_to_onos_cli(log_dir, log_file, cmd, host='localhost'):
    output = open(log_dir + '/' + log_file, 'w')
    child = pexpect.spawn('ssh -p 30115 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no karaf@%s' % host)
    child.expect('[pP]assword:')
    child.sendline('karaf')
    # Expected prompt:
    #  onos>          (ONOS 1.x)
    #  karaf@root >   (ONOS 2.x)
    child.expect(['(\\x1b\[\d*;?\d+m){1,2}onos> (\\x1b\[\d*;?\d+m){1,2}', 'karaf@root >'])
    child.sendline(cmd)
    child.expect(['(\\x1b\[\d*;?\d+m){1,2}onos> (\\x1b\[\d*;?\d+m){1,2}', 'karaf@root >'])

    output.write(child.before)
    
    output.close()
    child.close()


def get_fields_from_grep_command(self, search_word, log_file):
    grepCommand =\
        "grep %s %s/%s" % (search_word, get_dir(self, 'log'), log_file)
    statusLines = commands.getstatusoutput(grepCommand)[1]
    return statusLines
    

def parse_fields(status_line, delimiter):
    statusList = status_line.split(delimiter)
    return statusList


def print_log_file(self, log_file):
    with open(get_dir(self, 'log') + '/' + log_file, 'r+') as FILE:
        lines = FILE.readlines()
        print
        for line in lines:
            sys.stdout.write(line)


def extract_pod_ip_addr(pod_name):
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'svc', '--all-namespaces'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-e', pod_name], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc3 = subprocess.Popen(['awk', "{print $4}"], stdin=proc2.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
                            
    proc1.stdout.close()
    proc2.stdout.close()
    out, err = proc3.communicate()
    return out
    

def extract_radius_ip_addr(pod_name):
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'describe', 'pod', '-n', 'voltha', pod_name],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '^IP:'], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc3 = subprocess.Popen(['awk', "{print $2}"], stdin=proc2.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

    proc1.stdout.close()
    proc2.stdout.close()
    out, err = proc3.communicate()
    return out
    

def extract_pod_name(short_pod_name):
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'pods', '--all-namespaces'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-e', short_pod_name], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc3 = subprocess.Popen(['awk', "{print $2}"], stdin=proc2.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

    proc1.stdout.close()
    proc2.stdout.close()
    out, err = proc3.communicate()
    return out
    

def modify_radius_ip_in_json_using_sed(self, new_ip_addr):
    sedCommand = "sed -i '/radiusIp/c\      \"radiusIp\":\"'%s'\",' %s/tests/atests/build/aaa_json" \
                 % (new_ip_addr, get_dir(self, 'voltha'))
    status = commands.getstatusoutput(sedCommand)[0]
    return status


def discover_rg_pod_name():
    return extract_pod_name('rg0').strip()


def retrieve_authorized_users_device_id_and_port_number(status_line):
    fields = parse_fields(status_line, ',')
    deviceField = fields[2].strip()
    deviceStr, equal, deviceId = deviceField.partition('=')
    device_Id = deviceId
    portField = fields[4].strip()
    portNumStr, equal, portNum = portField.partition('=')
    portNumber = portNum
    return device_Id, portNumber


def add_subscriber_access(self, device_id, port_number):
    send_command_to_onos_cli(get_dir(self, 'log'),
                             'voltha_add_subscriber_access.log', 'volt-add-subscriber-access %s %s'
                             % (device_id, port_number))
