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
Library           ../common/dhcp.py
Library           ../common/unicast.py
Library           volthaMngr.VolthaMngr
Library           preprovisioning.Preprovisioning
Library           discovery.Discovery
Library           authentication.Authentication
Library           dhcp.DHCP
Library           unicast.Unicast

Suite Setup        Start Voltha      
Suite Teardown     Stop Voltha

*** Variables ***
${LOG_DIR}              /tmp/voltha_test_results
${ROOT_DIR}             ${EMPTY}
${VOLTHA_DIR}           ${EMPTY}
${OLT_PORT_ID}          50060
${OLT_TYPE}             ${EMPTY}
${ONU_TYPE}             ${EMPTY}
${OLT_HOST_IP}          ${EMPTY}
${ONU_COUNT}            ${EMPTY}
${SIMTYPE}              ${EMPTY}
${RETRY_TIMEOUT_60}     60s
${RETRY_INTERVAL_2}     2s
${PROCEED_TIMEOUT_180}  180s


*** Test Cases ***
Olt Pre Provisioning
    [Documentation]     Olt Pre Provisioning
    ...                 This test preprovisions a ponsim-OLT with given IP address and TCP port 
    ...                 and then enables both it and a number of ponsim-ONUs with predefined IP/port
    ...                 information. It then verifies that all the physical and logical devices are ACTIVE
    ...                 and REACHEABLE
    P Set Log Dirs      ${LOG_DIR}
    P Configure         ${OLT_HOST_IP}    ${OLT_PORT_ID}    ${OLT_TYPE}    ${ONU_TYPE}  ${ONU_COUNT}
    Preprovision Olt
    Wait Until Keyword Succeeds    ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Query Devices Before Enabling
    Status Should Be Success After Preprovision Command
    Check Olt Fields Before Enabling
    Enable
    Wait Until Keyword Succeeds    ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Validate Number of Devices
    Wait Until Keyword Succeeds   ${PROCEED_TIMEOUT_180}  ${RETRY_INTERVAL_2}    Proceed

Olt Onu Discovery
    [Documentation]     Olt Onu Discovery
    ...                 This test covers both Onu Discovery and yet to be developped Olt Discovery
    ...                 It aims to verify the integrity of all port fields under each discrete device, including
    ...                 Logical Device.
    ...                 It also insures that the peers fields contains device Id entries for the corresponding 
    ...                 Olt or Onu device. Functionality to support multiple ONU accomodated
    ...                 The extent of the flow validation is limited to checking whether number of Flows is > 0
    D Set Log Dirs      ${LOG_DIR}
    D Configure         ${OLT_HOST_IP}  ${OLT_TYPE}    ${ONU_TYPE}  ${ONU_COUNT}
    Olt Discovery
    Onu Discovery
    Logical Device
    Logical Device Ports Should Exist
    Logical Device Should Have At Least One Flow
    Olt Ports Should Be Enabled and Active
    Onu Ports Should Be Enabled and Active
    Olt Should Have At Least One Flow
    Onu Should Have At Least One Flow
    
Radius Authentication
    [Documentation]     Radius Authentication
    ...                 This test attempts to perform a Radius Authentication from the RG in the case
    ...                 of the 'ponsim' simtype. It uses the wpa_supplicant app to authenticate using EAPOL.
    ...                 We then verify the generated log file confirming all the authentication steps
    ...                 In the case where the simtype is 'bbsim' we simply verify that all ONUs have
    ...                 authenticated. We do this by executing the 'aaa-users command on onos
    A Set Log Dirs      ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    A Configure         ${ONU_COUNT}
    Run Keyword If      '${SIMTYPE}' == 'ponsim'      Ponsim Authentication Steps
    ...  ELSE IF        '${SIMTYPE}' == 'bbsim'       BBSim Authentication Verification Step

Dhcp IP Address Assignment
    [Documentation]     DHCP assigned IP Address
    ...                 In the case where the simtype is 'ponsim' we do the following:
    ...                 A DHCP server is configured and Activated on Onos. We need to change
    ...                 the Firewall rules so as to allow packets to flow between RG and OLT/ONU
    ...                 We also must add a second DHCP flow rule in onos in the direction from NNI
    ...                 by calling 'add subscriber access' on onos. We then deassign the default
    ...                 IP address granted to RG upon instantiating the RG pod. Finally we invoke
    ...                 'dhclient' on RG to request a DHCP IP address.
    ...                 In the case where the symtype is 'bbsim' we simply confirm that all ONUs
    ...                 were assigned an IP address. This happens automatically once all ONUs have
    ...                 been authenticated and the DHCP requests transition between the bbsim
    ...                 dhclient, dhcp server via the dhcpl2relay
    [Tags]    nc
    H Set Log Dirs      ${ROOT_DIR}     ${VOLTHA_DIR}    ${LOG_DIR}
    H Configure         ${ONU_COUNT}
    Run Keyword If      '${SIMTYPE}' == 'ponsim'      Ponsim DHCP Steps
    ...  ELSE IF        '${SIMTYPE}' == 'bbsim'       BBSim DHCP Verification Step

Unicast flow setup ctag/stag assignment
    [Documentation]     Unicast ctag/stag assignment
    ...                 We call Ping from RG to a non-existant IP address an we ignore the
    ...                 Destination Host Unreachable message. We then invoke tcpdump on 'pon1'
    ...                 network looking for ARP request from RG IP address. These packets should
    ...                 be double tagged with different s and c Tags but matching tag configuration
    ...                 in sadis entry.
    [Tags]              ponsim
    U Set Log Dirs      ${ROOT_DIR}     ${VOLTHA_DIR}    ${LOG_DIR}
    U Configure         ${ONU_TYPE}     ${ONU_COUNT}
    Read Sadis Entries From Sadis Json
    Retrieve Onu Serial Numbers
    Manage Onu Testing

*** Keywords ***
Start Voltha
    [Documentation]     Start Voltha infrastructure to run test(s). This includes starting all 
    ...                 Kubernetes Pods and start collection of logs. PonsimV2 has now been
    ...                 containerized and does not need to be managed separately
    ...                 Initialize working DIRs as well as Simtype specific variables. We also 
    ...                 setup Freeradius and restart AAA app in onos in preparation for 
    ...                 authentication test case
    ${ROOT_DIR}  ${VOLTHA_DIR}  ${LOG_DIR}  Dir Init    ${LOG_DIR}
    Set Suite Variable  ${ROOT_DIR}
    Set Suite Variable  ${VOLTHA_DIR}
    Set Suite Variable  ${LOG_DIR}   
    V Set Log Dirs      ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    ${OLT_TYPE}  ${ONU_TYPE}    ${OLT_HOST_IP}  ${ONU_COUNT}  Simtype Init  ${SIMTYPE}
    Set Suite Variable  ${OLT_TYPE}
    Set Suite Variable  ${ONU_TYPE}
    Set Suite Variable  ${OLT_HOST_IP}
    Set Suite Variable  ${ONU_COUNT}
    Stop Voltha
    Start All Pods      ${SIMTYPE}
    Sleep    60
    ${pod_status}       Run    kubectl get pods --all-namespaces
    Log To Console      \n${pod_status}\n
    Alter Onos Net Cfg
    Discover Freeradius Pod Name
    Discover Freeradius Ip Addr
    Prepare Current Freeradius Ip
    Alter Freeradius Ip In Onos AAA Application Configuration
    Deactivate Aaa App In Onos
    Sleep   5
    Activate Aaa App In Onos

Stop Voltha
    [Documentation]     Stop Voltha infrastructure. This includes clearing all installation milestones
    ...                 files and stopping all Kubernetes pods
    Collect Pod Logs
    Stop All Pods       ${SIMTYPE}
    Reset Kube Adm      ${SIMTYPE}

Ponsim Authentication Steps
    [Documentation]     List of steps required to run manual Authentication from RG
    Execute Authentication On RG
    Authentication Should Have Started
    Authentication Should Have Completed
    Authentication Should Have Disconnected
    Authentication Should Have Terminated

BBSim Authentication Verification Step
    [Documentation]     List of steps to verify that all BBSim ONUs have successfully authenticated
    Wait Until Keyword Succeeds    ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Should Have All Onus Authenticated
   
Validate Number of Devices
    [Documentation]     Validate the number of expected onus to be activated
    Query Devices After Enabling
    Status Should Be Success After Enable Command
    Check Olt Fields After Enabling
    Check Onu Fields After Enabling 

Ponsim DHCP Steps
    [Documentation]     List of steps required to run DHCP IP Address Assignment on RG
    Set Firewall Rules
    Discover Authorized Users
    Extract Authorized User Device Id And Port Number
    Add Onu Bound Dhcp Flows
    Should Now Have Two Dhcp Flows
    Add Dhcp Server Configuration Data In Onos
    Activate Dhcp Server In Onos
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Query For Default Ip On Rg
    De Assign Default Ip On Rg
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Assign Dhcp Ip Addr To Rg
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Should Have Dhcp Assigned Ip

BBSim DHCP Verification Step
    [Documentation]     Validate that all ONUs were assigned an IP address
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}     Should Have Ips Assigned To All Onus
