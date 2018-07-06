# M10 - Verify DHCP Lookup

## Test Objective

* Purpose of this test is to verify RG can successfully setup DHCP session

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT should be reachable to VOLTHA over IP interface over VLAN 4092
* Maple OLT should be in active state on VOLTHA
* Broadcom ONU should be in active state on VOLTHA
* RG is authenticated with Radius
* DHCP, Unicast and IGMP forwarding flows are setup on OLT and ONU
* DHCP Server is running

## Test Procedure

* Enable DHCP on RG by either resetting or enable/disable port
* DHCP Request from should be forwarded by VOLTHA/ONOS to DHCP Server
* OLT will send and receive DHCP Messages with SVID 4091 towards VOLTHA/ONOS
* DHCP should succeed and RG should have IP address
* Verify ARP, PING and Traceroute succeeds from RG to DHCP server (Not planned on it will be additional step)

## Pass/Fail Criteria

* RG can receive IP address from DHCP server
* ARP, Ping and Traceroute is successful between RG and DHCP server
