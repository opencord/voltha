# T27 - Traffic Recovers After ToR Switch Reset (Best Effort)

## Test Objective

* Purpose of this test is to verify reset/reboot of TOR switch is able to recover the traffic 

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Now reset /reboot the TOR switch
* Verify TOR is up, Traffic is restored successfully 

## Pass / Fail Criteria

* Traffic should stop flowing when TOR switch is restarted. Once the TOR switch is up, Traffic restored successfully on the ONU
