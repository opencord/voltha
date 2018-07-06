# M17 - Spirent - Verify IPv4 Unicast Streams Downstream

## Test Objective

* Purpose of this test is to verify OLT and ONU can handle double tagged traffic 

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* On Spirent, configure double tagged traffic in downstream direction (1025,1025)
* On Spirent, send untagged traffic in upstream direction 
* On the both ports capture traffic and verify the stream 

## Pass / Fail Criteria

* Upstream: 
    * configure on the Spirent side to send traffic with NO vlan 
    * OLT and ONT will add 1025 ,1025 respectively (i.e. 1025,1025)
* Downstream:
    * configure on the Spirent side to send traffic with 1025,1025
    * OLT will strip the 1025 and send traffic to corresponding ONT ( i.e. 1025 to ONT)
