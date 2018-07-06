# T23 - Overnight Traffic Test

## Test Objective

* Purpose of this test is to verify overnight traffic test went through successfully with zero drops

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA
* Provision Multicast/IGMP service on the ONU from VOLTHA

## Test Procedure

* Send bi-directional data and multicast traffic over night and monitor for traffic drops

## Pass / Fail Criteria

* Bi-directional traffic went through overnight and no traffic drops 
