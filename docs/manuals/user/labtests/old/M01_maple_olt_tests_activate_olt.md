# M1 - Preprovision and Activate OLT

## Test Objective

* Purpose of this test is to verify new OLT can be added and activated from VOLTHA
* VOLTHA will connect with OLT physical device and create a logical device with initial ports in its data store.
* VOLTHA will send Event notifications to ONOS and PON Manager for the newly added OLT

## Test Configuration

* Test Setup is as shown in Section – 7
* Maple OLT should be reachable to VOLTHA over IP interface on VLAN 4092

## Test Procedure

* Issue commands to VOLTHA to simulate “Add-OLT device” message coming from PON Manager on VOLTHA
* VOLTHA should initiate connect / activate request to Maple OLT
* VOLHA will create Logical Device and Ports, and notify ONOS
* Verify the PON Management traffic between VOLTHA and OLT is tagged with Management VLAN 4092
* VOLTHA will send OLT-Activated event notification to PON Manager 
* Verify OLT/ONU Status on Device Console
* ONU should drop all the traffic coming from RG 

## Pass/Fail Criteria

* OLT is successfully detected and activated on VOLTHA
* Logical device and port list is created on VOLTHA and ONOS
* OLT / ONU status can be seen from Device Console
