# M16 - Spirent - Verify 802.1ad (QinQ) Downstream

## Test Objective

* Purpose of this test is to verify OLT (DNX) can strip SVID from the incoming packets and forward only with CVID to ONU 

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* On Spirent, configure double tagged traffic in downstream direction (1025,1025)
* On the receiving port, capture traffic and verify the VLAN parameters 

## Pass/Fail Criteria

* Downstream:
    * configure on the Spirent side to send traffic with 1025,1025
    * OLT will strip the 1025 and send traffic to corresponding ONT ( i.e. 1025 to ONT)
    * Captured frame should contain only one VLAN tag (1025 VLAN)
