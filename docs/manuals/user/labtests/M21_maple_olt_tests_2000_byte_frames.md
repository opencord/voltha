# M21 - 2000 byte Frames

## Test Objective

* Purpose of this test is to verify OLT and ONU can accept and forward traffic when frame size of 2000 bytes

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Send data/unicast traffic with frame size of 2000 Bytes in upstream and downstream direction

## Pass / Fail Criteria

* OLT & ONU can accept and forward frames of size 2000 Bytes successfully 
