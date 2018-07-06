# S1 - Preprovision and Activate PONSIM Voltha

## Test Objective

* Purpose of this test is to verify new PONSIM OLT can be added and activated from VOLTHA, including;
    * Correct simulated PON environment
    * Logical device visible in VOLTHA CLI

## Test Configuration

* VOLTHA ensemble running as per [deployment instructions](V01_voltha_bringup_deploy.md).

## Test Procedure

Start off by starting ponsim, make sure you do this as root as ponsim creates virtual interfaces and adds some of them into the _ponmgmt_ bridge on the system.

```shell
 sudo -s
 . ./env.sh
 ./ponsim/main.py -v
```

PONSIM should now be running; check this by doing the following.

```shell
 sudo netstat -uteap | grep python
```

and you should see

```shell
tcp6       0      0 [::]:50060              [::]:*                  LISTEN      root       256217      19162/python
```

The above output also shows that PONSIM is waiting for gRPC connections which is what VOLTHA uses to talk to the simulated environment.

Next, let's check that PONSIM initialized correctly and added the correct interfaces to the _ponmgmt_ bridge.

```shell
brctl show ponmgmt
```

This should return the following output:

```shell
bridge name    bridge id          STP enabled     interfaces
ponmgmt        8000.02429b8631d5  no              pon1_0veth24f4706 (<- name may vary)
```

At this point we are ready to launch the voltha CLI and add the simulated OLT and ONU.

```shell
 ./cli/main.py -L
         _ _   _            ___ _    ___
__ _____| | |_| |_  __ _   / __| |  |_ _|
\ V / _ \ |  _| ' \/ _` | | (__| |__ | |
 \_/\___/_|\__|_||_\__,_|  \___|____|___|
(to exit type quit or hit Ctrl-D)
(voltha)
```

We have now a CLI to voltha, let's check if voltha is healthy. Enter the following at the CLI prompt.

```shell
health
```

which should return;

```json
{
    "state": "HEALTHY"
}
```

Now we can provision the PONSIM OLT and ONU in voltha. This is done in the voltha CLI.

```shell
preprovision_olt -t ponsim_olt -H 172.17.0.1:50060
```

This tells voltha to provision an olt of type ponsim_olt. You should see the following output.

```shell
success (device id = dece8e843be5)
```

The value of the device id may vary from run to run.

Next, we need to activate the OLT in voltha.

```shell
enable
```

which returns

```shell
activating dece8e843be5
success (logical device id = 1)
```

This has now activated both a ponsim olt and onu as can be seem by running the following command at the CLI.

```shell
devices
```

and the output should be

```shell
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
|           id |       type | root |    parent_id | vlan | admin_state | oper_status | connect_status | parent_port_no |    host_and_port | proxy_address.device_id | proxy_address.channel_id |
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
| dece8e843be5 | ponsim_olt | True |            1 |      |     ENABLED |      ACTIVE |      REACHABLE |                | 172.17.0.1:50060 |                         |                          |
| 56a6fc8b859f | ponsim_onu | True | dece8e843be5 |  128 |     ENABLED |      ACTIVE |      REACHABLE |              1 |                  |            dece8e843be5 |                      128 |
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
```

Also we can observe similar output at the REST API. To use the REST, open a new shell to the server and run the following command.  Note: The port number needs to be the recorded port number from the VOLTHA installation.

```shell
curl -s http://localhost:32863/api/v1/logical_devices  | jq .
```

and the output should be

```json
{
  "items": [
    {
      "datapath_id": "1",
      "root_device_id": "dece8e843be5",
      "switch_features": {
        "auxiliary_id": 0,
        "n_tables": 2,
        "datapath_id": "0",
        "capabilities": 15,
        "n_buffers": 256
      },
      "id": "1",
      "ports": [],
      "desc": {
        "dp_desc": "n/a",
        "sw_desc": "simualted pon",
        "hw_desc": "simualted pon",
        "serial_num": "46da01fd646d4bb08140fc09b1bc4926",
        "mfr_desc": "cord project"
      }
    }
  ]
}
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
/sbin/wpa_supplicant -Dwired -ipon1_128 -c /etc/wpa_supplicant/wpa_supplicant.conf
```

this should hang with the following output. You will need to interrupt it with Ctrl-C.

```shell
Successfully initialized wpa_supplicant
eth1: Associated with 01:80:c2:00:00:03
WMM AC: Missing IEs
```

and in the ponsim console you should see

```shell
20170113T053529.328 DEBUG    frameio.recv {iface: pon1_128sim, hex: 0180c20000037a61e2a73004888e01010000, len: 18, event: frame-received, instance_id: pon1}
20170113T053529.329 DEBUG    frameio.recv {event: frame-dispatched, instance_id: pon1}
20170113T053529.329 DEBUG    frameio._dispatch {frame: 0180c20000037a61e2a73004888e01010000, event: calling-publisher, instance_id: pon1}
20170113T053529.330 DEBUG    realio.ingress {frame: 0180c20000037a61e2a73004888e01010000, port: 128, iface_name: pon1_128sim, event: ingress, instance_id: pon1}
20170113T053529.330 DEBUG    ponsim.ingress {logical_port_no: 128, name: onu0, ingress_port: 2, event: ingress, instance_id: pon1}
20170113T053529.330 DEBUG    ponsim.ingress {logical_port_no: 128, name: onu0, event: dropped, instance_id: pon1}
```

## Pass/Fail Criteria

* OLT is successfully detected and activated on VOLTHA
* Logical device and port list is created on VOLTHA
* OLT and ONU should be visible in VOLTHA CLI
* OLT and ONU should be visible in VOLTHA REST API
* EAPOL Authentication should hang
