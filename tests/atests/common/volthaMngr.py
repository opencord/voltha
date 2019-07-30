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
import subprocess
import testCaseUtils
import logging
import time


class VolthaMngr(object):

    """
    This class implements voltha startup/shutdown callable helper functions
    """

    DEFAULT_SIMTYPE = 'ponsim'

    def __init__(self):
        self.dirs = dict()
        self.dirs['root'] = None
        self.dirs['voltha'] = None
        self.dirs['log'] = None

        self.__radiusName = None
        self.__radiusIp = None

    def v_set_log_dirs(self, root_dir, voltha_dir, log_dir):
        testCaseUtils.config_dirs(self, log_dir, root_dir, voltha_dir)

    def start_all_pods(self, simtype=DEFAULT_SIMTYPE):
        proc1 = subprocess.Popen([testCaseUtils.get_dir(self, 'root') + '/build.sh', 'start', simtype],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close()

    def stop_all_pods(self, simtype=DEFAULT_SIMTYPE):
        proc1 = subprocess.Popen([testCaseUtils.get_dir(self, 'root') + '/build.sh', 'stop', simtype],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close()
        
    def reset_kube_adm(self, simtype=DEFAULT_SIMTYPE):
        proc1 = subprocess.Popen([testCaseUtils.get_dir(self, 'root') + '/build.sh', 'clear', simtype],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        output = proc1.communicate()[0]
        print(output)
        proc1.stdout.close()

    """
    Because we are not deploying SEBA with XOS and NEM, and that a standalone Voltha
    deployment is not common, in order to get flows to work, we need to alter Onos 
    NetCfg in two fashion.
    One is to add to device list and the other is to add the missing Sadis section
    """        
    def alter_onos_net_cfg(self):
        logging.info('Altering the Onos NetCfg to suit Voltha\'s needs')
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/devices/ -d @%s/tests/atests/build/devices_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/devices/ -d @%s/tests/atests/build/devices_json'
                  % testCaseUtils.get_dir(self, 'voltha'))
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/sadis_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/sadis_json'
                  % testCaseUtils.get_dir(self, 'voltha'))
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/dhcpl2relay_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/dhcpl2relay_json'
                  % testCaseUtils.get_dir(self, 'voltha'))

    def collect_pod_logs(self):
        logging.info('Collect logs from all Pods')
        allRunningPods = get_all_running_pods()
        for nsName in allRunningPods:
            Namespace = nsName.get('NS')
            podName = nsName.get('Name')
            if 'onos' in podName:
                os.system('/usr/bin/kubectl logs -n %s -f %s onos > %s/%s.log 2>&1 &' %
                          (Namespace, podName, testCaseUtils.get_dir(self, 'log'), podName))
            elif 'calico-node' in podName:
                os.system('/usr/bin/kubectl logs -n %s -f %s calico-node > %s/%s.log 2>&1 &' %
                          (Namespace, podName, testCaseUtils.get_dir(self, 'log'), podName))
            else:
                os.system('/usr/bin/kubectl logs -n %s -f %s > %s/%s.log 2>&1 &' %
                          (Namespace, podName, testCaseUtils.get_dir(self, 'log'), podName))

    def discover_freeradius_pod_name(self):
        self.__radiusName = testCaseUtils.extract_pod_name('freeradius').strip()
        logging.info('freeradius Name = %s' % self.__radiusName)

    def discover_freeradius_ip_addr(self):
        ipAddr = testCaseUtils.extract_radius_ip_addr(self.__radiusName)
        assert ipAddr, 'No IP address listed for freeradius'
        self.__radiusIp = ipAddr.strip()
        logging.info('freeradius IP = %s' % self.__radiusIp)

    def prepare_current_freeradius_ip(self):
        status = testCaseUtils.modify_radius_ip_in_json_using_sed(self, self.__radiusIp)
        assert (status == 0), 'Setting Radius Ip in Json File did not return Success'

    def alter_freeradius_ip_in_onos_aaa_application_configuration(self):
        logging.info('Altering the Onos NetCfg AAA apps with Freeradius IP address')
        logging.debug('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                      'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/aaa_json'
                      % testCaseUtils.get_dir(self, 'voltha'))
        os.system('curl --user karaf:karaf -X POST -H "Content-Type: application/json" '
                  'http://localhost:30120/onos/v1/network/configuration/apps/ -d @%s/tests/atests/build/aaa_json'
                  % testCaseUtils.get_dir(self, 'voltha'))

    def activate_aaa_app_in_onos(self):
        logging.info('Activating AAA Application on Onos')
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_aaa_application_activate.log', 'app activate aaa')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Activated', 'voltha_aaa_application_activate.log')
        assert statusLines, 'AAA Application failed to be Activated'

    def deactivate_aaa_app_in_onos(self):
        logging.info('Deactivating AAA Application on Onos')
        testCaseUtils.send_command_to_onos_cli(testCaseUtils.get_dir(self, 'log'),
                                               'voltha_aaa_application_deactivate.log', 'app deactivate aaa')
        statusLines = testCaseUtils.get_fields_from_grep_command(self, 'Deactivated', 'voltha_aaa_application_deactivate.log')
        assert statusLines, 'AAA Application failed to be Deactivated'


def get_all_running_pods():
    allRunningPods = []
    proc1 = subprocess.Popen(['/usr/bin/kubectl', 'get', 'pods', '--all-namespaces'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-v', 'NAMESPACE'], stdin=proc1.stdout,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()
    print(out)
    if out:
        for line in out.split('\n'):
            items = line.split()
            if len(items) > 2:
                nsName = dict()
                nsName['NS'] = items[0]
                nsName['Name'] = items[1]
                allRunningPods.append(nsName)
    return allRunningPods


def voltha_initialize(root_dir, voltha_dir, log_dir, simtype):
    voltha = VolthaMngr()
    voltha.v_set_log_dirs(root_dir, voltha_dir, log_dir)
    voltha.stop_all_pods(simtype)
    voltha.reset_kube_adm(simtype)
    voltha.start_all_pods(simtype)
    voltha.alter_onos_net_cfg()
    voltha.collect_pod_logs()
    voltha.discover_freeradius_pod_name()
    voltha.discover_freeradius_ip_addr()
    voltha.prepare_current_freeradius_ip()
    voltha.alter_freeradius_ip_in_onos_aaa_application_configuration()
    voltha.deactivate_aaa_app_in_onos()
    time.sleep(5)
    voltha.activate_aaa_app_in_onos()
