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
Library           OperatingSystem
Library           ../common/auto_test.py
Library           ../common/volthaMngr.py
Library           ../common/preprovisioning.py
Library           volthaMngr.VolthaMngr
Library           preprovisioning.Preprovisioning
Test Setup        Start Voltha      
Test Teardown     Stop Voltha

*** Variables ***
${LOG_DIR}        /tmp/voltha_test_results
${ROOT_DIR}       ${EMPTY}
${VOLTHA_DIR}     ${EMPTY}
${PONSIM_PID}     ${EMPTY}
${ONOS_SSH_PORT}  8101
${OLT_IP_ADDR}    olt.voltha.svc
${OLT_PORT_ID}    50060


*** Test Cases ***
Provisioning
    [Documentation]     VOLTHA Pre-provisioning
    ...                 This test preprovisions a ponsim-OLT with given IP address and TCP port 
    ...                 and then enables both it and a number of ponsim-ONUs with predefined IP/port
    ...                 information. It then verifies that all the physical and logical devices are ACTIVE
    ...                 and REACHEABLE
    PSet Log Dirs    ${LOG_DIR}
    Configure   ${OLT_IP_ADDR}    ${OLT_PORT_ID}
    Preprovision Olt
    Wait Until Keyword Succeeds    60s    2s    Query Devices Before Enable
    Enable
    Wait Until Keyword Succeeds    60s    2s    Query Devices After Enable


*** Keywords ***
Start Voltha
    [Documentation]     Start Voltha infrastructure to run test(s). This includes starting all 
    ...                 Kubernetes Pods and start collection of logs. PonsimV2 has now been
    ...                 containerized and does not need to be managed separately
    ${ROOT_DIR}  ${VOLTHA_DIR}  ${LOG_DIR}      Dir Init    ${LOG_DIR}
    VSet Log Dirs  ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    Stop Voltha
    Start All Pods
    Sleep    60
    Collect Pod Logs
    ${pod_status}    Run    kubectl get pods --all-namespaces
    Log To Console    \n ${pod_status}
    Alter Onos NetCfg
    
Stop Voltha
    [Documentation]     Stop Voltha infrastucture. This includes clearing all installation milestones 
    ...                 files and stopping all Kubernetes pods
    Stop All Pods
    Reset Kube Adm 
