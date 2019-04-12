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
${ADAPTER}              ${EMPTY}
${RETRY_TIMEOUT_60}     60s
${RETRY_INTERVAL_2}     2s

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
    Wait Until Keyword Succeeds    ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Query Devices After Enabling
    Status Should Be Success After Enable Command
    Check Olt Fields After Enabling
    Check Onu Fields After Enabling
    Sleep    60

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
    ...                 This test attempts to perform a Radius Authentication from the RG
    ...                 It uses the wpa_supplicant app to authenticate using EAPOL.
    ...                 We then verify the generated log file confirming all the authentication steps
    [Tags]              ponsim
    A Set Log Dirs      ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    Discover Freeradius Pod Name
    Discover Freeradius Ip Addr
    Set Current Freeradius Ip In AAA Json
    Alter AAA Application Configuration In Onos Using AAA Json
    Execute Authentication On RG
    Verify Authentication Should Have Started
    Verify Authentication Should Have Completed
    Verify Authentication Should Have Disconnected
    Verify Authentication Should Have Terminated    

Dhcp IP Address Assignment on RG
    [Documentation]     DHCP assigned IP Address
    ...                 A DHCP server is configured and Activated on Onos. We need to change
    ...                 the Firewall rules so as to allow packets to flow between RG and OLT/ONU
    ...                 We also must add a second DHCP flow rule in onos in the direction from NNI
    ...                 by calling 'add subscriber access' on onos. We then deassign the default
    ...                 IP address granted to RG upon instantiating the RG pod. Finally we invoke
    ...                 'dhclient' on RG to request a DHCP IP address.
    [Tags]              ponsim
    H Set Log Dirs      ${ROOT_DIR}     ${VOLTHA_DIR}    ${LOG_DIR}
    Set Firewall Rules
    Discover Authorized Users
    Retrieve Authorized Users Device Id And Port Number
    Add Subscriber Access
    Should Now Have Two Dhcp Flows
    Add Dhcp Server Configuration Data In Onos
    Activate Dhcp Server In Onos
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Query For Default Ip On Rg
    De Assign Default Ip On Rg
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Assign Dhcp Ip Addr To Rg
    Wait Until Keyword Succeeds  ${RETRY_TIMEOUT_60}    ${RETRY_INTERVAL_2}    Should Have Dhcp Assigned Ip

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
    ...                 Initialize working DIRs as well as Adapter specific variables
    ${ROOT_DIR}  ${VOLTHA_DIR}  ${LOG_DIR}  Dir Init    ${LOG_DIR}
    Set Suite Variable  ${ROOT_DIR}
    Set Suite Variable  ${VOLTHA_DIR}
    Set Suite Variable  ${LOG_DIR}   
    V Set Log Dirs      ${ROOT_DIR}    ${VOLTHA_DIR}    ${LOG_DIR}
    ${OLT_TYPE}  ${ONU_TYPE}    ${OLT_HOST_IP}  ${ONU_COUNT}  Adapter Init  ${ADAPTER}
    Set Suite Variable  ${OLT_TYPE}
    Set Suite Variable  ${ONU_TYPE}
    Set Suite Variable  ${OLT_HOST_IP}
    Set Suite Variable  ${ONU_COUNT}
    Stop Voltha
    Start All Pods      ${ADAPTER}
    Sleep    60
    ${pod_status}       Run    kubectl get pods --all-namespaces
    Log To Console      \n${pod_status}\n
    Alter Onos Net Cfg
    
Stop Voltha
    [Documentation]     Stop Voltha infrastructure. This includes clearing all installation milestones
    ...                 files and stopping all Kubernetes pods
    Collect Pod Logs
    Stop All Pods       ${ADAPTER}
    Reset Kube Adm      ${ADAPTER}
