# M4 - Verify DHCP successfully obtains an IP address

## Test Objective

* Purpose of this test is to verify that the Dynamic Host Configuration Protocol (DHCP)
    * Correct Maple OLT and ONU PON environment
    * Logical device visible in VOLTHA CLI

## Test Configuration

* VOLTHA ensemble running as per [deployment instructions](V01_voltha_bringup_deploy.md).
* Note: The DHCP server is contained within ONOS.
* Maple OLT and ONUs registered as ACTIVE in VOLTHA

## Test Procedure

To start this procedure, execute the "ifconfig" command on the interface that will be getting assigned an IP address over DHCP and verify that IP address has not been assigned. 

```shell
ifconfig eno1
```

Next, execute the following command to obtain an IP address from ONOS.

```shell
dhclient eno1
```
Note: When the dhclient command completes a common error message is displayed as follows.  This mesage can safely be ignored. 

```shell
dhclient: cannot move '/etc/*.conf' to '/etc/resolve.conf'
```

Then verify that an IP address was dynamically assigned to your interface

```shell
ifconfig eno1
```

## Pass/Fail Criteria

* IP address assigned to interface
