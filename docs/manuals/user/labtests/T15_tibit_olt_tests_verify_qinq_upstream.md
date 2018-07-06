# T15 - Spirent - Verify 802.1ad (QinQ) Upstream

## Test Objective

* Purpose of this test is to verify OLT can insert second VLAN tag (SVID) in upstream direction

## Test Configuration

* Test Setup as shown in Section – 7
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* On Spirent, send untagged traffic in upstream direction 
* On the receiving port end, capture traffic and verify the VLAN parameters 

## Pass/Fail Criteria

* Upstream: 
    * configure on the Spirent side to send untagged traffic (NO vlan  configure)
    * OLT and ONT will add 1025 ,1025 respectively (i.e. 1025,1025)
    * Captured frame should contain 1025, 1025 vlan
