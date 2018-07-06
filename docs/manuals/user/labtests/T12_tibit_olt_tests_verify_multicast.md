# T12 - Verify Multicast Access

## Test Objective

* To verify video service on RG

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT should be reachable to VOLTHA over IP interface on VLAN 4090
* Tibit OLT should be in active state on VOLTHA
* Tibit ONU should be in active state on VOLTHA
* RG is authenticated with Radius and RG has IP address from DHCP
* VLC streaming server is active, VLC Video Client is connected to RG

## Test Procedure

* Enable Multicast Video Stream from VLC server
* Multicast Video stream should be tagged with VLAN ID 140
* From VLC client initiate connection to streaming Multicast channel
* Packet Capture at OLT port should show IGMP join message
* Observe Video quality on TV 

## Pass/Fail Criteria

* Video is displayed on TV
