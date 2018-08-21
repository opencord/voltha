# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

*** Settings ***
Library           Process
Library           ../common/auto_test.py
Library           ../common/volthaMngr.py
Library           ../common/preprovisioningTest.py

Test Setup        Start Voltha      
Test Teardown     Stop Voltha


*** Variables ***
${LOG_DIR}        /tmp/voltha_test_results
${ROOT_DIR}       ${EMPTY}
${VOLTHA_DIR}     ${EMPTY}
${PONSIM_PID}     ${EMPTY}
${ONUS}           3
${ONOS_SSH_PORT}  8101
${OLT_IP_ADDR}    "172.17.0.1"
${OLT_PORT_ID}    50060


*** Test Cases ***
Provisioning
    [Documentation]     VOLTHA Pre-provisioning Test
    ...                 This test deploys an OLT port and a number of ONU ports 
    ...                 Then it verifies that all the physical and logical devices are up 
    Configure   ${OLT_IP_ADDR}    ${OLT_PORT_ID}    ${LOG_DIR}
    Preprovision Olt
    Query Devices Before Enable
    Enable
    Query Devices After Enable


*** Keywords ***
Start Voltha
    [Documentation]     Start Voltha infrastructure to run test(s). This includes starting all 
    ...                 Docker containers for Voltha and Onos as well as Ponsim. It then start 
    ...                 Voltha and Onos Cli
    ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}  Dir Init    ${LOG_DIR}
    Config Dir  ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    Stop Voltha
    Start Voltha Containers
    Collect All Logs
    Enable Bridge
    ${PONSIM_PID}   Start Ponsim  ${ONUS}
    Run Onos
    
    
Stop Voltha
    [Documentation]     Stop Voltha infrastucture. This includes stopping all Docker containers 
    ...                 for Voltha and Onos as well stopping Ponsim process.
    Stop Ponsim
    Remove Existing Containers
    
    
    
