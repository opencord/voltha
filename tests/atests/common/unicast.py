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
vOLT-HA Unicast Test Case module
"""

import time
import testCaseUtils
import logging
import subprocess
import json


class Unicast(object):
    """
    This class implements voltha Unicast test case
    """

    PING_TEST_FILENAME = 'voltha_ping_test.log'
    TCPDUMP_FILENAME = 'voltha_tcpdump.log'

    def __init__(self):
        self.dirs = dict()
        self.dirs['log'] = None
        self.dirs['root'] = None
        self.dirs['voltha'] = None

        self.__rgName = testCaseUtils.discover_rg_pod_name()
        self.__fields = None
        self.__tcpdumpPid = None
        self.__onuType = None
        self.__onuCount = None
        self.__onuSerialNum = []
        self.__sadisCTag = None
        self.__sadisSTag = None
        self.__datastore = None

    def u_set_log_dirs(self, root_dir, voltha_dir, log_dir):
        testCaseUtils.config_dirs(self, log_dir, root_dir, voltha_dir)

    def u_configure(self, onu_type, onu_count):
        self.__onuType = onu_type
        self.__onuCount = onu_count

    def execute_ping_test(self):
        logging.info('Ping 1.2.3.4 IP Test')
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.PING_TEST_FILENAME), 'w')
        pingTest = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-it', '-n', 'voltha', self.__rgName, '--',
                                    '/bin/ping', '-I', 'eth0', '1.2.3.4'],
                                    stdout=process_output,
                                    stderr=process_output)

        self.execute_tcpdump()

        self.kill_ping_test()

        pingTest.wait()
        process_output.close()

        testCaseUtils.print_log_file(self, self.PING_TEST_FILENAME)
        testCaseUtils.print_log_file(self, self.TCPDUMP_FILENAME)
        print

    def execute_tcpdump(self):
        logging.info('Execute tcpdump')
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.TCPDUMP_FILENAME), 'w')
        tcpdump = subprocess.Popen(['sudo', '/usr/sbin/tcpdump', '-nei', 'nni0'],
                                   stdout=process_output,
                                   stderr=process_output)
        self.__tcpdumpPid = tcpdump.pid

        time.sleep(20)

        self.kill_tcpdump()
        tcpdump.wait()
        process_output.close()

    def kill_ping_test(self):
        procPidPing1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'ps', '-ef'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        procPidPing2 = subprocess.Popen(['grep', '-e', '/bin/ping'], stdin=procPidPing1.stdout,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        procPidPing3 = subprocess.Popen(['awk', "{print $2}"], stdin=procPidPing2.stdout,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        procPidPing1.stdout.close()
        procPidPing2.stdout.close()

        out, err = procPidPing3.communicate()
        pingPid = out.strip()

        procKillPing = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'kill', pingPid],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        out, err = procKillPing.communicate()
        assert not err, 'Killing Ping returned %s' % err

    def kill_tcpdump(self):
        procKillTcpdump = subprocess.Popen(['sudo', 'pkill', '-P', str(self.__tcpdumpPid)],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        out, err = procKillTcpdump.communicate()
        assert not err, 'Killing Tcpdump returned %s' % err

    def ping_test_should_have_failed(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Destination Host Unreachable', self.PING_TEST_FILENAME)
        assert statusLines, 'Ping Test Issue, no Destination Host Unreachable'
        lineCount = 0
        lines = statusLines.splitlines()
        for line in lines:
            logging.debug(line)
            lineCount += 1
        if lineCount > 1:  # Must have 2 or more instances
            return True

    def stag_and_ctag_should_match_sadis_entry(self):
        logging.info('Evaluating sTag and cTag in each packet')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, '802.1Q', self.TCPDUMP_FILENAME)
        assert statusLines, 'tcpdump contains no 802.1Q tagged packets'
        lines = statusLines.splitlines()
        for line in lines:
            header, tagId, after = line.partition('802.1Q')
            self.__fields = testCaseUtils.parse_fields(after, ',')
            stag = self.__fields[1].strip().split(':')[1].strip().split()[1].strip()
            before, tagId, after = line.rpartition('802.1Q')
            self.__fields = testCaseUtils.parse_fields(after, ',')
            ctag = self.__fields[1].strip().split()[1].strip()
            self.stag_and_ctag_should_match_sadis_file(ctag, stag)

    def should_have_q_in_q_vlan_tagging(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, '"Request who-has"', self.TCPDUMP_FILENAME)
        assert statusLines, 'tcpdump contains no ping packets'
        lines = statusLines.splitlines()
        for line in lines:
            tagCount = line.count('802.1Q')
            assert tagCount == 2, 'Found a non double tagged packet'

    def retrieve_onu_serial_numbers(self):
        logging.info('Onu Serial Number Discovery')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, self.__onuType, 'voltha_devices_after_enable.log')
        assert statusLines, 'No Onu listed under devices'
        lines = statusLines.splitlines()
        assert len(lines) == self.__onuCount, 'Onu count mismatch found: %s, should be: %s' % (len(lines), self.__onuCount)
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line, '|')
            onuSerialNum = self.__fields[5].strip()
            self.__onuSerialNum.append(onuSerialNum)

    def retrieve_stag_and_ctag_for_onu(self, onu_serial_num):
        entries = self.__datastore['org.opencord.sadis']['sadis']['entries']
        for entry in entries:
            entry_id = entry['id']
            if entry_id == onu_serial_num:
                self.__sadisCTag = entry['cTag']
                self.__sadisSTag = entry['sTag']

    def read_sadis_entries_from_sadis_json(self):
        with open('%s/tests/atests/build/sadis_json' % testCaseUtils.get_dir(self, 'voltha'), 'r') as sadis:
            self.__datastore = json.load(sadis)

    def stag_and_ctag_should_match_sadis_file(self, ctag, stag):
        assert ctag == str(self.__sadisCTag) and stag == str(self.__sadisSTag), 'cTag and/or sTag do not match value in sadis file\n \
            vlan cTag = %s, sadis cTag = %s : vlan sTag = %s, sadis sTag = %s' % (ctag, self.__sadisCTag, stag, self.__sadisSTag)

    def manage_onu_testing(self):
        for onuSerial in self.__onuSerialNum:
            self.retrieve_stag_and_ctag_for_onu(onuSerial)
            self.execute_ping_test()
            self.ping_test_should_have_failed()
            self.should_have_q_in_q_vlan_tagging()
            self.stag_and_ctag_should_match_sadis_entry()


def run_test(onu_type, onu_count, root_dir, voltha_dir, log_dir):

    unicast = Unicast()
    unicast.u_set_log_dirs(root_dir, voltha_dir, log_dir)
    unicast.u_configure(onu_type, onu_count)
    unicast.read_sadis_entries_from_sadis_json()
    unicast.retrieve_onu_serial_numbers()
    unicast.manage_onu_testing()
