# T26 - Traffic Recovers After OLT Reset (Best Effort)

## Test Objective

* Purpose of this test is to verify reset/reboot of ONU is able to recover the traffic on the ONU

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Now reset /reboot the OLT
* Verify OLT is up, ONU ranges and traffic is restored successfully 

## Pass / Fail Criteria

* When OLT is up, ONU ranges back and traffic restores automatically on the ONU

