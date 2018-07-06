# T19 - 10k and 20k ONU Ranging

## Test Objective

* Purpose of this test is to verify ONU can range with 10km and 20 KM distance

## Test Configuration

* Test Setup is as shown in earlier sections

## Test Procedure

* Register the ONU with the OLT across a 10KM fiber spool
* Activate the OLT and ONU using VOLTHA 
* Confirm OLT and ONU have the oper_status of ```ACTIVE``` in VOLTHA
* Register the ONU with the OLT across a 20KM fiber spool
* Activate the OLT and ONU using VOLTHA 
* Confirm OLT and ONU have the oper_status of ```ACTIVE``` in VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA and send traffic 

## Pass / Fail Criteria

* OLT can range the ONU successfully with 10 KM distance 
* OLT can range the ONU successfully with 20 KM distance 
* Traffic flows successfully with 20 KM distance without any drops 
