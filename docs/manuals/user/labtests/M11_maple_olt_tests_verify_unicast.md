# M11 - Verify Unicast Access

## Test Objective

* Purpose of this test is to verify OLT and ONU can pass double tagged traffic 

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* On Spirent, configure double tagged traffic in downstream direction (1025,1025)
* On Spirent, send untagged traffic in upstream direction 
* On the both ports capture traffic and verify the stream 

## Pass/Fail Criteria

* Upstream: 
    * Traffic coming out of OLT is double tagged 1025 ,1025
* Downstream:
    * OLT will strip outer tag 1025 and send single CVID traffic to ONT
