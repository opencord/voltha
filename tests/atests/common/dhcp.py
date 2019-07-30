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
vOLT-HA DHCP Test Case module
"""

import os
import testCaseUtils
import logging
import subprocess


class DHCP(object):
    """
    This class implements voltha DHCP test case
    """

    CHECK_IP_FILENAME = 'voltha_check_ip.log'
    DE_ASSIGN_IP_FILENAME = 'voltha_de-assign_ip.log'
    ASSIGN_DHCP_IP_FILENAME = 'voltha_assign_dhcp_ip.log'
    CHECK_ASSIGNED_IP_FILENAME = 'voltha_check_assigned_dhcp_ip.log'

    def __init__(self):
        self.dirs = dict()
        self.dirs['log'] = None
        self.dirs['root'] = None
        self.dirs['voltha'] = None

        self.__rgName = testCaseUtils.discover_rg_pod_name()
        self.__onuCount = None
        self.__fields = None
        self.__deviceId = None
        self.__portNumber = None

    def h_set_log_dirs(self, root_dir, voltha_dir, log_dir):
        testCaseUtils.config_dirs(self, log_dir, root_dir, voltha_dir)

    def h_configure(self, onu_count):
        self.__onuCount = onu_count

    def discover_authorized_users(self):
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_onos_users.log', 'aaa-users')

    def extract_authorized_user_device_id_and_port_number(self):
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'AUTHORIZED', 'voltha_onos_users.log')
        assert statusLines, 'No ONU has been authenticated'
        self.__deviceId, self.__portNumber = testCaseUtils.retrieve_authorized_users_device_id_and_port_number(statusLines)

    def add_onu_bound_dhcp_flows(self):
        testCaseUtils.add_subscriber_access(self, self.__deviceId, self.__portNumber)

    def should_now_have_two_dhcp_flows(self):
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_onos_flows.log', 'flows -s')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'IP_PROTO:17', 'voltha_onos_flows.log')
        assert statusLines, 'No DHCP Detection flows'
        lines = statusLines.splitlines()
        assert len(lines) >= 2, 'Expected at least 2 DHCP Detection Flows but result was %s' % len(lines)
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line, ',')
            inPortStr = self.__fields[5].strip()
            selector, delimiter, inPort = inPortStr.partition('=[')
            assert (inPort == 'IN_PORT:2' or inPort == 'IN_PORT:128'), 'DHCP detection flows not associated with expected ports'

    def add_dhcp_server_configuration_data_in_onos(self):
        logging.info('Adding DHCP Configuration Data to Onos NetCfg')
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/dhcp_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/dhcp_json'
                  % testCaseUtils.get_dir(self, 'voltha'))

    def activate_dhcp_server_in_onos(self):
        logging.info('Activating DHCP server on Onos')
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_dhcp_server_activate.log', 'app activate dhcp')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Activated', 'voltha_dhcp_server_activate.log')
        assert statusLines, 'DHCP server failed to be Activated'

    def deactivate_dhcp_server_in_onos(self):
        logging.info('Deactivating DHCP server on Onos')
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_dhcp_server_deactivate.log', 'app deactivate dhcp')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Deactivated', 'voltha_dhcp_server_deactivate.log')
        assert statusLines, 'DHCP server failed to be Deactivated'

    def query_for_default_ip_on_rg(self):
        logging.info('De-assigning default IP on RG')
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.CHECK_IP_FILENAME), 'w')
        ifconfigCheck1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'bash', '-c',
                                          'ifconfig'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        ifconfigCheck2 = subprocess.Popen(['grep', '-e', 'eth0', '-A1'], stdin=ifconfigCheck1.stdout,
                                          stdout=process_output,
                                          stderr=process_output)

        ifconfigCheck1.wait()
        ifconfigCheck1.stdout.close()
        ifconfigCheck2.wait()

        process_output.close()

        testCaseUtils.print_log_file(self, self.CHECK_IP_FILENAME)

    def de_assign_default_ip_on_rg(self):

        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'inet', self.CHECK_IP_FILENAME)
        if statusLines:
            process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.DE_ASSIGN_IP_FILENAME), 'w')
            os.system('/usr/bin/kubectl exec -n voltha %s -- bash -c "ifconfig eth0 0.0.0.0"' % self.__rgName)
            ifconfigDeassign1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'bash', '-c',
                                                 'ifconfig'],
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)

            ifconfigDeassign2 = subprocess.Popen(['grep', '-e', 'eth0', '-A1'], stdin=ifconfigDeassign1.stdout,
                                                 stdout=process_output,
                                                 stderr=process_output)
            ifconfigDeassign1.wait()
            ifconfigDeassign1.stdout.close()
            ifconfigDeassign2.wait()

            process_output.close()

            statusLines = testCaseUtils.get_fields_from_grep_command(self, 'inet', self.DE_ASSIGN_IP_FILENAME)
            assert not statusLines, 'IP addr not de-assigned'

        else:
            logging.info('No default IP addr assigned to eth0')

    def assign_dhcp_ip_addr_to_rg(self):
        logging.info('Assigning IP addr on RG using DHCP')
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.ASSIGN_DHCP_IP_FILENAME), 'w')
        dhcpAssignIp1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-it', '-n', 'voltha', self.__rgName, '--',
                                         'dhclient', '-v', 'eth0'],
                                         stdout=process_output,
                                         stderr=process_output)

        dhcpAssignIp1.wait()
        process_output.close()

        testCaseUtils.print_log_file(self, self.ASSIGN_DHCP_IP_FILENAME)

        procPidDhclient1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'ps', '-ef'],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
        procPidDhclient2 = subprocess.Popen(['grep', '-e', 'dhclient'], stdin=procPidDhclient1.stdout,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
        procPidDhclient3 = subprocess.Popen(['awk', "{print $2}"], stdin=procPidDhclient2.stdout,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)

        procPidDhclient1.stdout.close()
        procPidDhclient2.stdout.close()

        out, err = procPidDhclient3.communicate()
        dhclientPid = out.strip()
        if dhclientPid:
            procKillDhclient = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'kill', dhclientPid],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)

            out, err = procKillDhclient.communicate()
            assert not err, 'Killing dhclient returned %s' % err

    def should_have_dhcp_assigned_ip(self):
        process_output = open('%s/%s' % (testCaseUtils.get_dir(self, 'log'), self.CHECK_ASSIGNED_IP_FILENAME), 'w')
        ifConfigCheck1 = subprocess.Popen(['/usr/bin/kubectl', 'exec', '-n', 'voltha', self.__rgName, '--', 'bash', '-c',
                                          'ifconfig'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)

        ifConfigCheck2 = subprocess.Popen(['grep', '-e', 'eth0', '-A1'], stdin=ifConfigCheck1.stdout,
                                          stdout=process_output,
                                          stderr=process_output)
        ifConfigCheck1.wait()
        ifConfigCheck1.stdout.close()
        ifConfigCheck2.wait()

        process_output.close()

        testCaseUtils.print_log_file(self, self.CHECK_ASSIGNED_IP_FILENAME)

        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'inet', self.CHECK_ASSIGNED_IP_FILENAME)
        assert statusLines, 'DHCP IP addr not assigned'

    def should_have_ips_assigned_to_all_onus(self):
        logging.info('Verifying IP Address assignment on all ONUs')
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               '_voltha_onos_dhcpl2relay_allocations.log', 'dhcpl2relay-allocations')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'DHCPACK', '_voltha_onos_dhcpl2relay_allocations.log')
        assert statusLines, 'No DHCP addresses allocated'
        lines = statusLines.splitlines()
        assert len(lines) == self.__onuCount, 'Allocated IPs does not match ONU count but result was %s' % len(lines)
        for line in lines:
            self.__fields = testCaseUtils.parse_fields(line, ',')
            allocIp = self.__fields[5].strip()
            allocated, delimiter, ipAddr = allocIp.partition('=')
            assert ipAddr != '0.0.0.0', 'Invalid IP Address Allocated'


def set_firewall_rules():
    logging.info('Setting Firewall rules for DHCP test')
    os.system('sudo iptables -P FORWARD ACCEPT')


def run_test(onu_count, root_dir, voltha_dir, log_dir, simtype):
    dhcp = DHCP()
    dhcp.h_set_log_dirs(root_dir, voltha_dir, log_dir)
    dhcp.h_configure(onu_count)
    if simtype == 'ponsim':
        set_firewall_rules()
        dhcp.discover_authorized_users()
        dhcp.extract_authorized_user_device_id_and_port_number()
        dhcp.add_onu_bound_dhcp_flows()
        dhcp.should_now_have_two_dhcp_flows()
        dhcp.deactivate_dhcp_server_in_onos()
        dhcp.add_dhcp_server_configuration_data_in_onos()
        dhcp.activate_dhcp_server_in_onos()
        dhcp.query_for_default_ip_on_rg()
        dhcp.de_assign_default_ip_on_rg()
        dhcp.assign_dhcp_ip_addr_to_rg()
        dhcp.should_have_dhcp_assigned_ip()
    elif simtype == 'bbsim':
        dhcp.should_have_ips_assigned_to_all_onus()
