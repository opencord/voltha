# M24 - Traffic Recovers After Fiber Disconnect (Best Effort)

## Test Objective

* Purpose of this test is to verify pull & re-insert of PON cable can resume the traffic on the ONU

## Test Configuration

* Test Setup as shown in Section – 7
* Maple OLT and ONU is activated using VOLTHA
* Provision HSIA/unicast service on the OLT and connected ONU from VOLTHA

## Test Procedure

* Now manually pull the fiber cable the from ONU
* Re-insert the fiber cable to the ONU and verify ONU is ranges and traffic restores

## Pass / Fail Criteria

* Traffic stopped when cable is pulled from ONU
* After cable insert, ONU is ranged back and traffic starts flowing automatically on the ONU
