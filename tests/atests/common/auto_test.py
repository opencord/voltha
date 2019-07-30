#!/usr/bin/python2

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
vOLT-HA Automated Testing module
"""
import os
import time
import argparse
import volthaMngr
import preprovisioning
import discovery
import authentication
import dhcp
import unicast
import logging

DEFAULT_LOG_DIR = '/tmp/voltha_test_results'
DEFAULT_SIMTYPE = 'ponsim'
logging.basicConfig(level=logging.INFO)


def dir_init(log_dir=DEFAULT_LOG_DIR, voltha_dir=os.environ['VOLTHA_BASE']):
    """

    :param log_dir: default log dir
    :param voltha_dir: voltha base dir
    :return: root_dir, voltha_dir, log_dir
    """
    logging.info(__file__)

    """   
    Init automated testing environment and return three directories: root dir,
    voltha sources dir and log dir
    """

    root_dir = os.path.abspath(os.path.dirname(__file__))

    currentTime = time.strftime("%Y-%m-%d-%H-%M-%S")

    # In future in order to keep the history of jobs, the run time should be
    # added to the log directory name
    # logDir += '_' + currentTime
 
    os.system('mkdir -p ' + log_dir + ' > /dev/null 2>&1')
    os.system('rm -rf %s/*' % log_dir)
    logging.info('Starting Voltha Test Case Suite at: %s\nRoot Directory: %s\n'
                 'VOLTHA Directory: %s\nLog Directory: %s' %
                 (currentTime, root_dir, voltha_dir, log_dir))

    return root_dir, voltha_dir, log_dir


def simtype_init(simtype=DEFAULT_SIMTYPE):
    """

    :param simtype: ponsim or bbsim
    :return: olt_type, onu_type, olt_host_ip, onu_count
    """
    if simtype == 'ponsim':
        olt_type = 'ponsim_olt'
        onu_type = 'ponsim_onu'
        olt_host_ip = 'olt0.voltha.svc'
        onu_count = 1
    elif simtype == 'bbsim':
        olt_type = 'openolt'
        onu_type = 'brcm_openomci_onu'
        olt_host_ip = 'bbsim.voltha.svc'
        onu_count = 16
    else:
        olt_type = None
        onu_type = None
        olt_host_ip = None
        onu_count = 0

    return olt_type, onu_type, olt_host_ip, onu_count


#
# MAIN
#
if __name__ == "__main__":
    """
    Main entry point of the automated testing when executed directly
    """

    parser = argparse.ArgumentParser(description='VOLTHA Automated Testing')
    parser.add_argument('-l', dest='logDir', default=DEFAULT_LOG_DIR,
                        help='log directory (default: %s).' % DEFAULT_LOG_DIR)
    parser.add_argument('-a', dest='simtype', choices=['ponsim', 'bbsim'], default=DEFAULT_SIMTYPE,
                        help='simtype (default: %s).' % DEFAULT_SIMTYPE)
    args = parser.parse_args()

    ROOT_DIR, VOLTHA_DIR, LOG_DIR = dir_init(args.logDir)
    OLT_TYPE, ONU_TYPE, OLT_HOST_IP, ONU_COUNT = simtype_init(args.simtype)
    
    volthaMngr.voltha_initialize(ROOT_DIR, VOLTHA_DIR, LOG_DIR, args.simtype)

    preprovisioning.run_test(OLT_HOST_IP, 50060, OLT_TYPE, ONU_TYPE, ONU_COUNT, LOG_DIR)

    discovery.run_test(OLT_HOST_IP, OLT_TYPE, ONU_TYPE, ONU_COUNT, LOG_DIR)

    authentication.run_test(ONU_COUNT, ROOT_DIR, VOLTHA_DIR, LOG_DIR, args.simtype)

    dhcp.run_test(ONU_COUNT, ROOT_DIR, VOLTHA_DIR, LOG_DIR, args.simtype)

    if args.simtype == 'ponsim':
        unicast.run_test(ONU_TYPE, ONU_COUNT, ROOT_DIR, VOLTHA_DIR, LOG_DIR)
