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
import logging

DEFAULT_LOG_DIR = '/tmp/voltha_test_results'
logging.basicConfig(level=logging.INFO)


def dir_init(log_dir=DEFAULT_LOG_DIR, voltha_dir=os.environ['VOLTHA_BASE']):
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
    args = parser.parse_args()

    ROOT_DIR, VOLTHA_DIR, LOG_DIR = dir_init(args.logDir)
    
    volthaMngr.voltha_initialize(ROOT_DIR, VOLTHA_DIR, LOG_DIR)

    preprovisioning.run_test('olt.voltha.svc', 50060, 'ponsim_olt', 'ponsim_onu', LOG_DIR)
    
    discovery.run_test('olt.voltha.svc', 'ponsim_olt', 'ponsim_onu', LOG_DIR)

    authentication.run_test(ROOT_DIR, VOLTHA_DIR, LOG_DIR)

    dhcp.run_test(ROOT_DIR, VOLTHA_DIR, LOG_DIR)

    time.sleep(5)
