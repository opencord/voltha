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

DEFAULT_LOG_DIR = '/tmp/voltha_test_results'

def dirInit(logDir=DEFAULT_LOG_DIR,
         volthaDir=os.environ['VOLTHA_BASE']):
    print(__file__)
    """
    Init automated testing environment and return three directories: root dir,
    voltha sources dir and log dir
    """

    rootDir = os.path.abspath(os.path.dirname(__file__))

    currentTime = time.strftime("%Y-%m-%d-%H-%M-%S")

    # In future in order to keep the history of jobs, the run time should be
    # added to the log directory name
    # logDir += '_' + currentTime
    
    os.system('mkdir -p ' + logDir + ' > /dev/null 2>&1')
    os.system('rm -rf %s/*' % logDir)
    print('Start Provisioning Test at: %s\nRoot Directory: %s\n'
          'VOLTHA Directory: %s\nLog Directory: %s' %
          (currentTime, rootDir, volthaDir, logDir))

    return rootDir, volthaDir, logDir


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

    ROOT_DIR, VOLTHA_DIR, LOG_DIR = dirInit(args.logDir)

    volthaMngr.voltha_Initialize(ROOT_DIR, VOLTHA_DIR, LOG_DIR)

    preprovisioning.runTest('olt.voltha.svc', 50060, LOG_DIR)

    time.sleep(5)
