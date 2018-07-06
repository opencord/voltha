# T25 - Traffic Recovers After ONU Reset (Best Effort)

## Test Objective

* Purpose of this test is to verify reset/reboot of ONU is able to recover the traffic on the ONU

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Now manually reset /reboot the ONU
* Verify whether ONU ranges and traffic is restored successfully 

## Pass / Fail Criteria

* Traffic should stop flowing when ONU is restarted
* After ONU is up, traffic restores automatically on the ONU
