# M18 - Spirent - Verify IPv4 Unicast Streams Downstream Case2

## Test Objective

* Purpose of this test is to verify P-BIT parameter is propagated to C-VID when sending downstream traffic to ONU

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* On Spirent, configure P-BIT for CVID. ex: set P-BIT value to 3 
* On the Receive port end, capture traffic and verify the P-BIT parameter on SVID  in Up stream direction 

## Pass / Fail Criteria

* P-BIT value s-VID is copied to C-VID in downstream direction 
