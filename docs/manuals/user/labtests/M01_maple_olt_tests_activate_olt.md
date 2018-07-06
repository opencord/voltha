# M1 - Preprovision and activate OLT

## Test Objective

* Purpose of this test is to verify a new OLT can be added and activated from VOLTHA
* VOLTHA will connect with the OLT physical device and create a logical device with initial ports in its data store
* VOLTHA will send Event notifications to ONOS and PON Manager for the newly added OLT

## Test Configuration

* The test setup is as shown in earlier sections
* Maple OLT should be reachable from VOLTHA on VLAN 4092

## Temporary Configuration

* The following commands are temporary and will be removed when full
  support in added to VOLTHA. The following commands add and verify
  the VLAN 4092 interface to VOLTHA along with an IP address in the
  subnet used to communicate with the Maple OLT.

```shell
docker exec -ti compose_voltha_1 bash
ip link add link eth1 name eth1.4092 type vlan id 4092
ip addr add 192.168.24.20/24 brd + dev eth1.4092
ip link set eth1.4092 up
apt install -y iputils-ping
ping 192.168.24.10
exit
```

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
* Note: for the purposes of this document the OLT IP address is assumed
  to be 192.168.24.10

```shell
preprovision_olt --device-type=maple_olt --ip-address=192.168.24.10
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
+--------------+-----------+---------------+----------------+
|           id |      type |  ipv4_address |    admin_state |
+--------------+-----------+---------------+----------------+
| 32dd2fa5827d | maple_olt | 192.168.24.10 | PREPROVISIONED |
+--------------+-----------+---------------+----------------+
```

* To activate the OLT, execute the following command

```shell
enable
```

* VOLTHA should initiate a connection and activation request to the Maple OLT
* VOLHA will create the logical OpenFlow device and ports and notify ONOS
* VOLTHA will send an OLT-Activated event notification to the PON Manager
* VOLTHA will automatically provision and activate a single ONU
* Note: the automatic provisioning and activation of the single ONU is only temporary and will be replaced by ONU discovery and activation in a future release.

* Verify the OLT and ONU status on device console with the following command

```shell
devices
```

* The output should appear similar to the following

```shell
Devices:
+--------------+--------------+------+--------------+------+---------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
|           id |         type | root |    parent_id | vlan |  ipv4_address | admin_state | oper_status | connect_status | parent_port_no | proxy_address.device_id | proxy_address.channel_id |
+--------------+--------------+------+--------------+------+---------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
| 32dd2fa5827d |    maple_olt | True |            1 |      | 192.168.24.10 |     ENABLED |      ACTIVE |      REACHABLE |                |                         |                          |
| a957b19f955c | broadcom_onu | True | 32dd2fa5827d | 1025 |               |     ENABLED |      ACTIVE |      REACHABLE |              1 |            32dd2fa5827d |                     1025 |
+--------------+--------------+------+--------------+------+---------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
```

* Activating the ONU currently initiates an OMCI exchange between
  the OLT and ONU. In addition, EAPOL, IGMP and DHCP forwarding rules
  are installed.
* Note: the automatic initiation of OMCI messaging and installation of
  forwarding rules is temporary and will be driven by flow rules in
  a future release.

Now that this OLT has provisioned all forwarding rules, it should continue to drop all traffic since ONOS is not running. We can verify this by starting the RG emulator and observing that EAPOL authentication does not succeed. To do this start our RG docker container.

```shell
docker run --net=host --privileged --name RG -it voltha/tester bash
```

this should land you in a command prompt that looks like

```shell
root@8358ef5cad0e:/#
```

and at this prompt issue the following command

```shell
/sbin/wpa_supplicant -Dwired -ieno1 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

this should hang with the following output. You will need to interrupt it with Ctrl-C.

```shell
Successfully initialized wpa_supplicant
eno1: Associated with 01:80:c2:00:00:03
WMM AC: Missing IEs
```

## Pass/Fail Criteria

* OLT / ONUs status can be seen from Device Console
* Confirm OLT and ONUs have "oper_status" of ACTIVE
* ONUs should not authenticate
