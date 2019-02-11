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
Library           ../common/discovery.py
Library           ../common/authentication.py
Library           volthaMngr.VolthaMngr
Library           preprovisioning.Preprovisioning
Library           discovery.Discovery
Library           authentication.Authentication

Suite Setup        Start Voltha      
Suite Teardown     Stop Voltha

*** Variables ***
${LOG_DIR}        /tmp/voltha_test_results
${ROOT_DIR}       ${EMPTY}
${VOLTHA_DIR}     ${EMPTY}
${ONOS_SSH_PORT}  8101
${OLT_IP_ADDR}    olt.voltha.svc
${OLT_PORT_ID}    50060
${LOGICAL_TYPE}   olt.voltha.svc
${OLT_TYPE}       ponsim_olt
${ONU_TYPE}       ponsim_onu

*** Test Cases ***
Olt Pre Provisioning
    [Documentation]     Olt Pre Provisioning
    ...                 This test preprovisions a ponsim-OLT with given IP address and TCP port 
    ...                 and then enables both it and a number of ponsim-ONUs with predefined IP/port
    ...                 information. It then verifies that all the physical and logical devices are ACTIVE
    ...                 and REACHEABLE
    PSet Log Dirs    ${LOG_DIR}
    PConfigure   ${OLT_IP_ADDR}    ${OLT_PORT_ID}    ${OLT_TYPE}    ${ONU_TYPE} 
    Preprovision Olt
    Wait Until Keyword Succeeds    60s    2s    Query Devices Before Enabling
    Status Should Be Success After Preprovision Command
    Check Olt Fields Before Enabling
    Enable
    Wait Until Keyword Succeeds    60s    2s    Query Devices After Enabling
    Status Should Be Success After Enable Command
    Check Olt Fields After Enabling
    Check Onu Fields After Enabling
    
Olt Onu Discovery
    [Documentation]     Olt Onu Discovery
    ...                 This test covers both Onu Discovery and yet to be developped Olt Discovery
    ...                 It aims to verify the integrity of all port fields under each discrete device.
    ...                 It also insures that the peers fields contains device Id entries for the corresponding 
    ...                 Olt or Onu device. Functionality to support multiple ONU accomodated
    ...                 The extent of the flow validation is limited to checking whether number of Flows is > 0
    DSet Log Dirs    ${LOG_DIR}
    DConfigure      ${LOGICAL_TYPE}    ${OLT_TYPE}    ${ONU_TYPE}
    Olt Discovery
    Onu Discovery
    Logical Device
    Olt Ports Should Be Enabled and Active
    Onu Ports Should Be Enabled and Active
    Olt Should Have At Least One Flow
    Onu Should Have At Least One Flow
    
Radius Authentication
    [Documentation]     Radius Authentication
    ...                 This test attempts to perform a Radius Authentication from the RG
    ...                 It uses the wpa_supplicant app to authenticate using EAPOL.
    ...                 We then verify the generated log file confirming all the authentication steps
    ASet Log Dirs    ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    Discover RG Pod Name
    Discover Freeradius Pod Name
    Discover Freeradius Ip Addr
    Set Current Freeradius Ip In AAA Json
    Alter AAA Application Configuration In Onos Using AAA Json
    Execute Authenticatication On RG
    Verify Authentication Should Have Started
    Verify Authentication Should Have Completed
    Verify Authentication Should Have Disconnected
    Verify Authentication Should Have Terminated    

*** Keywords ***
Start Voltha
    [Documentation]     Start Voltha infrastructure to run test(s). This includes starting all 
    ...                 Kubernetes Pods and start collection of logs. PonsimV2 has now been
    ...                 containerized and does not need to be managed separately
    ${ROOT_DIR}  ${VOLTHA_DIR}  ${LOG_DIR}      Dir Init    ${LOG_DIR}
    Set Suite Variable  ${ROOT_DIR}
    Set Suite Variable  ${VOLTHA_DIR}
    Set Suite Variable  ${LOG_DIR}   
    VSet Log Dirs  ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    Stop Voltha
    Start All Pods
    Sleep    60
    ${pod_status}    Run    kubectl get pods --all-namespaces
    Log To Console    \n ${pod_status}
    Alter Onos NetCfg
    
Stop Voltha
    [Documentation]     Stop Voltha infrastucture. This includes clearing all installation milestones 
    ...                 files and stopping all Kubernetes pods
    Collect Pod Logs
    Stop All Pods
    Reset Kube Adm 
