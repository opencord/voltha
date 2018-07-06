# M19 - 10k and 20k ONU Ranging

## Test Objective

* Purpose of this test is to verify ONU can range with 10km and 20 KM distance

## Test Configuration

* Test Setup as shown in Section – 7

## Test Procedure

* Place the ONU Using 10KM fiber pool, Activate the OLT and ONU using VOLTHA
* Place the ONU Using 20KM fiber pool, Activate the OLT and ONU using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA and send traffic 

## Pass / Fail Criteria

* OLT can range the ONU successfully with 10 KM distance 
* OLT can range the ONU successfully with 20 KM distance 
* Traffic flows successfully with 20 KM distance without any drops 
