# V3 - Connect to Voltha via its CLI

## Test Objective

* Verify Voltha CLI is available
* Provide an introduction to the CLI, since it is used in many of the other testcases

## Test Configuration

* Voltha ensemble is instantiated (V1)

## Test Procedure

Start the Voltha CLI:

```shell
cd $VOLTHA_BASE
./cli/main.py -L
```

You should see it launched:
```shell
         _ _   _            ___ _    ___
__ _____| | |_| |_  __ _   / __| |  |_ _|
\ V / _ \ |  _| ' \/ _` | | (__| |__ | |
 \_/\___/_|\__|_||_\__,_|  \___|____|___|
(to exit type quit or hit Ctrl-D)
(voltha)
```

This places the user into normal mode, signified by the *(voltha)* prompt.

To check connectivity to Voltha and to check if Voltha is "healthy", run:

```shell
health
```

The expected output is:

```json
{
    "state": "HEALTHY"
}
```

To list all Voltha adapters, type:

```shell
adapters
```

This should show the loaded adapters:

```shell
Adapters:
+---------------+---------------------------+---------+------------------+
|            id |                    vendor | version | config.log_level |
+---------------+---------------------------+---------+------------------+
|  broadcom_onu |            Voltha project |     0.1 |             INFO |
|     maple_olt |            Voltha project |     0.1 |             INFO |
|    ponsim_olt |            Voltha project |     0.4 |             INFO |
|    ponsim_onu |            Voltha project |     0.4 |             INFO |
| simulated_olt |            Voltha project |     0.1 |             INFO |
| simulated_onu |            Voltha project |     0.1 |             INFO |
|     tibit_olt | Tibit Communications Inc. |     0.1 |             INFO |
|     tibit_onu | Tibit Communications Inc. |     0.1 |             INFO |
+---------------+---------------------------+---------+------------------+
```

There are many more commands available in the CLI. To list all commands
in *voltha* mode, type:

```shell
help
```

This will show the available commands:

```shell
(voltha) help

Documented commands (type help <topic>):
========================================
enable        edit     load             preprovision_olt  save       test
adapters      health   logical_device   py                set
device        history  logical_devices  reset_history     shell
devices       launch   pause            restart           shortcuts
ed            list     pdb              run               show

Undocumented commands:
======================
EOF  eof  exit  help  quit
```

## Brief Reference of Frequently Used CLI Commands

* Please note at this point in the test sequence there are no OLTs/ONUs, hence the output of these commands will in fact show empty tables; some commands are not even available.

To list all logical devices:

```shell
logical_devices
```

*Example* output:

```shell
(voltha) logical_devices
Logical devices:
+----+-------------+----------------+----------------------------------+---------------------------+--------------------------+
| id | datapath_id | root_device_id |                  desc.serial_num | switch_features.n_buffers | switch_features.n_tables |
+----+-------------+----------------+----------------------------------+---------------------------+--------------------------+
|  1 |           1 |   5a324e1c3996 | cc293bbceb974ce0a9314a7bd6f17ac0 |                       256 |                        2 |
+----+-------------+----------------+----------------------------------+---------------------------+--------------------------+
```

To list all physical devices:

```shell
devices
```

*Example* output:

```shell
(voltha) devices
Devices:
+--------------+---------------+------+--------------+------+-------------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
|           id |          type | root |    parent_id | vlan |       mac_address | admin_state | oper_status | connect_status | parent_port_no | proxy_address.device_id | proxy_address.channel_id |
+--------------+---------------+------+--------------+------+-------------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
| 5a324e1c3996 | simulated_olt | True |            1 |      | 00:0c:e2:31:40:00 |     ENABLED |      ACTIVE |      REACHABLE |                |                         |                          |
| 6e898ddc5e99 | simulated_onu |      | 5a324e1c3996 |  101 |                   |     ENABLED |      ACTIVE |      REACHABLE |              1 |            5a324e1c3996 |                      101 |
| 58089597a87b | simulated_onu |      | 5a324e1c3996 |  102 |                   |     ENABLED |      ACTIVE |      REACHABLE |              1 |            5a324e1c3996 |                      102 |
| 45de16e1c63b | simulated_onu |      | 5a324e1c3996 |  103 |                   |     ENABLED |      ACTIVE |      REACHABLE |              1 |            5a324e1c3996 |                      103 |
| fe80c1ca2c1b | simulated_onu |      | 5a324e1c3996 |  104 |                   |     ENABLED |      ACTIVE |      REACHABLE |              1 |            5a324e1c3996 |                      104 |
+--------------+---------------+------+--------------+------+-------------------+-------------+-------------+----------------+----------------+-------------------------+--------------------------+
```

To pre-provision an OLT of a certain type (e.g., maple with given IP address):

```shell
preprovision_olt -t maple_olt -i 10.11.12.13
```

*Example* output:

```shell
(voltha) preprovision_olt -t maple_olt -i 10.11.12.13
success (device id = 5a324e1c3996)
```

To activate the last pre-provisioned OLT:

```shell
enable
```

*Example* output:

```shell
(voltha) enable
activating 5a324e1c3996
waiting for device to be activated...
success (logical device id = 1)
```

To activate an OLT given by its ID:

```shell
enable <ID>
```

*Example* output:

```shell
(voltha) enable
activating 5a324e1c3996
waiting for device to be activated...
success (logical device id = 1)
```

To enter into a logical device context/mode:

```shell
logical_device <logical-device-ID>
```

*Example* output:

```shell
(voltha) logical_device 1
(logical device 1)
```

This will change the prompt to (logical device ```<ID>```).

Subcommands of logical device mode:

To show more info:

```shell
show
```

*Example* output:

```shell
(logical device 1) show
Logical device 1
+------------------------------+----------------------------------+
|                        field |                            value |
+------------------------------+----------------------------------+
|                           id |                                1 |
|                  datapath_id |                                1 |
|                desc.mfr_desc |                     cord porject |
|                 desc.hw_desc |                    simualted pon |
|                 desc.sw_desc |                    simualted pon |
|              desc.serial_num | cc293bbceb974ce0a9314a7bd6f17ac0 |
|                 desc.dp_desc |                              n/a |
|    switch_features.n_buffers |                              256 |
|     switch_features.n_tables |                                2 |
| switch_features.capabilities |                               15 |
+------------------------------+----------------------------------+
|               root_device_id |                     5a324e1c3996 |
|                        ports |                        5 item(s) |
+------------------------------+----------------------------------+
```

To list all ports of the logical device:

```shell
ports
```

*Example* output:

```shell
(logical device 1) ports
Logical device ports:
+-----+--------------+----------------+-----------+------------------+----------------------+---------------+----------------+---------------+---------------------+
|  id |    device_id | device_port_no | root_port | ofp_port.port_no |     ofp_port.hw_addr | ofp_port.name | ofp_port.state | ofp_port.curr | ofp_port.curr_speed |
+-----+--------------+----------------+-----------+------------------+----------------------+---------------+----------------+---------------+---------------------+
| nni | 5a324e1c3996 |              2 |      True |              129 | [0, 0, 0, 0, 0, 129] |           nni |              4 |          4128 |                  32 |
| 101 | 6e898ddc5e99 |              2 |           |              101 | [0, 0, 0, 0, 0, 101] |       uni-101 |              4 |          4128 |                  32 |
| 102 | 58089597a87b |              2 |           |              102 | [0, 0, 0, 0, 0, 102] |       uni-102 |              4 |          4128 |                  32 |
| 103 | 45de16e1c63b |              2 |           |              103 | [0, 0, 0, 0, 0, 103] |       uni-103 |              4 |          4128 |                  32 |
| 104 | fe80c1ca2c1b |              2 |           |              104 | [0, 0, 0, 0, 0, 104] |       uni-104 |              4 |          4128 |                  32 |
+-----+--------------+----------------+-----------+------------------+----------------------+---------------+----------------+---------------+---------------------+
```

To list all flows defined:

```shell
flows
```

*Example* output:

```shell
(logical device 1) flows
Logical Device 1 (type: n/a)
Flows (11):
+----------+----------+--------+---------+----------+----------+----------+-----------+---------+----------+--------------+----------+-----------+-------+------------+------------+
| table_id | priority | cookie | in_port | vlan_vid | eth_type | ip_proto |  ipv4_dst | udp_dst | metadata | set_vlan_vid | pop_vlan | push_vlan | group |     output | goto-table |
+----------+----------+--------+---------+----------+----------+----------+-----------+---------+----------+--------------+----------+-----------+-------+------------+------------+
|        0 |     2000 |      0 |     101 |          |     888E |          |           |         |          |              |          |           |       | CONTROLLER |            |
|        0 |     1000 |      0 |         |          |      800 |        2 |           |         |          |              |          |           |       | CONTROLLER |            |
|        0 |     1000 |      0 |         |          |      800 |       17 |           |      67 |          |              |          |           |       | CONTROLLER |            |
|        0 |      500 |      0 |     129 |     1000 |          |          |           |         |       40 |              |      Yes |           |       |            |          1 |
|        0 |      500 |      0 |     129 |      101 |          |          |           |         |          |            0 |          |           |       |        101 |            |
|        0 |      500 |      0 |     101 |        0 |          |          |           |         |          |          101 |          |           |       |            |          1 |
|        0 |      500 |      0 |     101 | untagged |          |          |           |         |          |          101 |          |      8100 |       |            |          1 |
|        0 |      500 |      0 |     101 |      101 |          |          |           |         |          |         1000 |          |      8100 |       |        129 |            |
|        0 |     1000 |      0 |     129 |      140 |      800 |          | 228.1.1.1 |         |          |              |          |           |     1 |            |            |
|        0 |     1000 |      0 |     129 |      140 |      800 |          | 228.2.2.2 |         |          |              |          |           |     2 |            |            |
+----------+----------+--------+---------+----------+----------+----------+-----------+---------+----------+--------------+----------+-----------+-------+------------+------------+
|        0 |     1000 |      0 |     129 |      140 |      800 |          | 228.3.3.3 |         |          |              |          |           |     3 |            |            |
+----------+----------+--------+---------+----------+----------+----------+-----------+---------+----------+--------------+----------+-----------+-------+------------+------------+
```

To exit logical device mode:

```shell
exit
```

*Example* output:

```shell
(logical device 1) exit
(voltha)
```

To enter into a device context/mode:

```shell
device <device-ID>
```

*Example* output:

```shell
(voltha) device 5a324e1c3996
(device 5a324e1c3996)
```

Subcommands of device mode:

To show device info:

```shell
show
```

*Example* output:

```shell
(device 5a324e1c3996) show
Device 5a324e1c3996
+------------------+----------------------------------+
|            field |                            value |
+------------------+----------------------------------+
|               id |                     5a324e1c3996 |
|             type |                    simulated_olt |
|             root |                             True |
|        parent_id |                                1 |
|           vendor |                        simulated |
|            model |                              n/a |
| hardware_version |                              n/a |
| firmware_version |                              n/a |
| software_version |                              1.0 |
|    serial_number | a90723b46a474a128369694c644101d3 |
+------------------+----------------------------------+
|          adapter |                    simulated_olt |
|      mac_address |                00:0c:e2:31:40:00 |
|      admin_state |                          ENABLED |
|      oper_status |                           ACTIVE |
|   connect_status |                        REACHABLE |
|            ports |                        2 item(s) |
|      flows.items |                        7 item(s) |
+------------------+----------------------------------+
```

To show all ports of device:
ports

*Example* output:

```shell
(device 45de16e1c63b) ports
Device ports:
+---------+--------------------------+--------------+-------------+-------------+--------------+------------------------------------------------+
| port_no |                    label |         type | admin_state | oper_status |    device_id |                                          peers |
+---------+--------------------------+--------------+-------------+-------------+--------------+------------------------------------------------+
|       2 | UNI facing Ethernet port | ETHERNET_UNI |     ENABLED |      ACTIVE | 45de16e1c63b |                                                |
|       1 |                 PON port |      PON_ONU |     ENABLED |      ACTIVE | 45de16e1c63b | [{'port_no': 1, 'device_id': u'5a324e1c3996'}] |
+---------+--------------------------+--------------+-------------+-------------+--------------+------------------------------------------------+
```

To show all flows defined on device:

```shell
flows
```

*Example* output:

```shell
(device 5a324e1c3996) flows
Device 5a324e1c3996 (type: simulated_olt)
Flows (7):
+----------+----------+--------+---------+----------+----------+----------+----------+---------+----------+--------------+----------+-----------+--------+
| table_id | priority | cookie | in_port | vlan_vid | vlan_pcp | eth_type | ip_proto | udp_dst | metadata | set_vlan_vid | pop_vlan | push_vlan | output |
+----------+----------+--------+---------+----------+----------+----------+----------+---------+----------+--------------+----------+-----------+--------+
|        0 |     2000 |      0 |       2 |     4000 |        0 |          |          |         |          |              |      Yes |           |      1 |
|        0 |     2000 |      0 |       1 |          |          |     888E |          |         |          |         4000 |          |      8100 |      2 |
|        0 |     1000 |      0 |       1 |          |          |      800 |        2 |         |          |         4000 |          |      8100 |      2 |
|        0 |     1000 |      0 |       1 |          |          |      800 |       17 |      67 |          |         4000 |          |      8100 |      2 |
|        0 |      500 |      0 |       2 |     1000 |          |          |          |         |       40 |              |      Yes |           |      1 |
|        0 |      500 |      0 |       1 |      101 |          |          |          |         |          |         1000 |          |      8100 |      2 |
|        0 |     1000 |      0 |       2 |      140 |          |          |          |         |          |              |      Yes |           |      1 |
+----------+----------+--------+---------+----------+----------+----------+----------+---------+----------+--------------+----------+-----------+--------+
```

To exit device mode:

```shell
exit
```

There is a "test" mode that allows installing various pre-manufactured flows, and removing all flows. This is strictly for integration testing:

To enter "test" mode from normal CLI mode:

```shell
test
```

In test mode all commands that are available in normal mode are still available, but in addition, there are some extra commands, such as:

To install just the EAPOL upstream forwarding flow:

```shell
install_eapol_flow [<logical-device-ID>]
```

To install all controller bound forwarding flows:

```shell
install_all_controller_bound_flows  [<logical-device-ID>]
```

To install all flows relevant in our use-case (upstream forwarding rules, unicast data flows, and a few multicast flows):

```shell
install_all_sample_flows  [<logical-device-ID>]
```

To remove all flows from a logical device:

```shell
delete_all_flows  [<logical-device-ID>]
```

Here is a sample CLI command sequence that preprovisions and activates an OLT, then downloads all sample flows and check the flows installed on the OLT device:

```shell
test
preprovision_olt -t maple_olt -i 10.11.12.13
enable
install_all_sample_flows
devices # to see the device IDs
device 123456789ab
flows
exit
```

## Pass/Fail Criteria

* CLI should start
* Health should show "HEALTHY"
* The adapters listed above are availble
