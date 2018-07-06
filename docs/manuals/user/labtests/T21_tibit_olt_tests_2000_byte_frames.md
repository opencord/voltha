# T21 - 9200 byte Frames

## Test Objective

* Purpose of this test is to verify OLT and ONU can accept and forward
  traffic when the frame size of equals 9200 bytes

## Test Configuration

* Test Setup is as shown in earlier sections
* Tibit OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Send data/unicast traffic with frame size of 9200 Bytes in upstream and downstream direction

## Pass / Fail Criteria

* OLT & ONU can accept and forward frames of size 9200 Bytes successfully 
