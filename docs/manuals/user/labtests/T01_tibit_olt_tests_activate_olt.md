# T1 - Preprovision and Activate OLT

## Test Objective

* Purpose of this test is to verify new OLT can be added and activated from VOLTHA
* VOLTHA will connect with the OLT physical device and create a
  logical device with initial ports in its data store
* VOLTHA will send Event notifications to ONOS and PON Manager for the newly added OLT

## Test Configuration

* The test setup is as shown in earlier sections
* Tibit OLT should be reachable from VOLTHA on VLAN 4090
* Start the VOLTHA CLI

## Step 1: If not yet running, launch the Voltha CLI

```shell
cd $VOLTHA_BASE
./cli/main.py -L
```

```shell
         _ _   _            ___ _    ___
__ _____| | |_| |_  __ _   / __| |  |_ _|
\ V / _ \ |  _| ' \/ _` | | (__| |__ | |
 \_/\___/_|\__|_||_\__,_|  \___|____|___|
(to exit type quit or hit Ctrl-D)
(voltha)
```

## Test Procedure

* Issue CLI commands in the VOLTHA CLI to simulate an “Add-OLT device”
  message coming from the PON Manager to VOLTHA
* Note: Please refer to the label for "MAC 0" printed on the side of
  the Tibit evaluation device to record the MAC address of the OLT

```shell
preprovision_olt --device-type tibit_olt --mac-address 00:0c:e2:31:40:00
```

* If the adapter for the device is found, VOLTHA will create the
  device in the device table. Executing the following command will
  display known devices

```shell
devices
```

* The output should appear as follows

```shell
Devices:
+--------------+-----------+-------------------+----------------+
|           id |      type |       mac_address |    admin_state |
+--------------+-----------+-------------------+----------------+
| 4dfe7799ae21 | tibit_olt | 00:0c:e2:31:40:00 | PREPROVISIONED |
+--------------+-----------+-------------------+----------------+
```

* To activate the OLT, execute the following command

```shell
enable
```

* VOLTHA should initiate a connection and activation request to the Tibit OLT
* VOLHA will create the logical OpenFlow device and ports and notify ONOS
* VOLTHA will send an OLT-Activated event notification to the PON Manager
* VOLTHA will also query the OLT for the number of ONUs connected and attempt to activate all ONUs
* Verify the OLT and ONU status on device console with the following command

```shell
devices
```

* The output should appear similar to the following

```shell
Devices:
+--------------+-----------+------+------+-------------------+-------------+-------------+...
|           id |      type | root | vlan |       mac_address | admin_state | oper_status |...
+--------------+-----------+------+------+-------------------+-------------+-------------+...
| ad2360e71312 | tibit_olt | True |      | 00:0c:e2:31:40:00 |     ENABLED |      ACTIVE |...
| 252bceddc720 | tibit_onu |      |  208 | 00:0c:e2:22:08:00 |     ENABLED |      ACTIVE |...
+--------------+-----------+------+------+-------------------+-------------+-------------+...
```

Now that this OLT has not received any forwarding rules, it should drop all traffic. We can verify this by starting the RG emulator and observing that EAPOL authentication does not succeed. To do this start our RG docker container.

```shell
docker run --net=host --privileged --name RG -it voltha/tester bash
```

this should land you in a command prompt that looks like

```shell
root@8358ef5cad0e:/#
```

and at this prompt issue the following command

```shell
/sbin/wpa_supplicant -Dwired -ieno4.2023 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

this should hang with the following output. You will need to interrupt it with Ctrl-C.

```shell
Successfully initialized wpa_supplicant
eth1: Associated with 01:80:c2:00:00:03
WMM AC: Missing IEs
```

## Pass/Fail Criteria

* OLT / ONUs status can be seen from Device Console
* Confirm OLT and ONUs have "oper_status" of ACTIVE
* ONUs should continue to drop all the traffic coming from RG
