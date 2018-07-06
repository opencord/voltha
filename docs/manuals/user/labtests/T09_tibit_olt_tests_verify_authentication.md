# T9 - Verify RG Authentication Scenario

## Test Objective

* Purpose of this test is to verify RG authentication is successful with Radius / EAP method

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT should be reachable to VOLTHA over IP interface over VLAN 4090
* Tibit OLT should be in active state on VOLTHA
* Tibit ONU should be in active state on VOLTHA
* EAPOL forwarding rule should be setup on OLT and ONU
* Radius Server is in service and configured to authenticate RG
* DHCP Server should be down

## Test Procedure

* Start EAP authentication process from RG by resetting RG.
* RG should send EAP-Start message and verify it reaches VOLTHA/ONOS
* EAP message exchange should happen between RG and VOLTHA/ONOS on Management VLAN 4091.
* VOLTHA/ONOS will use 802.1x method to authenticate RG EAP Identity with Radius Server
* Verify RG authentication is successful with EAP and 802.1x Radius methods
* After successful RG authentication,
* OLT/ONU should drop DHCP packets from RG
* VOLTHA/ ONOS should send DHCP Forwarding Flow to OLT and ONU
* VOLTHA/ ONOS should send Unicast Forwarding Flow to OLT and ONU
* VOLTHA/ ONOS should send IGMP Forwarding Flow to OLT and ONU
* OLT/ONU will be able to forward DHCP, Unicast and IGMP packets from RG 

## Pass/Fail Criteria

* RG is successfully authenticated based on its credentials in Radius Server
* DHCP, Unicast and IGMP forwarding flows are setup on OLT/ONU
