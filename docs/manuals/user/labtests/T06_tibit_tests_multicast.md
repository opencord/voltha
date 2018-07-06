# T6 - Test IGMP and multicast (Video) streams

## Test Objective

Verify that VOLTHA punts IGMP packets to ONOS and that ONOS provisions the right multicast rules

## Test Configuration

* VOLTHA ensemble up and running.
* Tibit configured with an OLT with one or more ONUs
* An authenticated RG

## Test Procedure

At this point ONOS should show the following rules.  Type flows at the 'onos>' prompt comfirm.

```shell
flows
```

```shell
deviceId=of:0000000000000001, flowRuleCount=7
    ADDED, bytes=0, packets=0, table=0, priority=10000, selector=[IN_PORT:128, ETH_TYPE:ipv4, IP_PROTO:2], treatment=[immediate=[OUTPUT:CONTROLLER]]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:128, ETH_TYPE:eapol], treatment=[immediate=[OUTPUT:CONTROLLER]]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:0, METADATA:80, VLAN_VID:1000], treatment=[immediate=[VLAN_POP:unknown], transition=TABLE:1]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:129, ETH_TYPE:eapol], treatment=[immediate=[OUTPUT:CONTROLLER]]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:128, VLAN_VID:0], treatment=[immediate=[VLAN_ID:128], transition=TABLE:1]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:130, ETH_TYPE:eapol], treatment=[immediate=[OUTPUT:CONTROLLER]]
    ADDED, bytes=0, packets=0, table=0, priority=1000, selector=[IN_PORT:128, ETH_TYPE:ipv4, IP_PROTO:17, UDP_SRC:68, UDP_DST:67], treatment=[immediate=[OUTPUT:CONTROLLER]]
    ADDED, bytes=0, packets=0, table=1, priority=1000, selector=[IN_PORT:0, VLAN_VID:128], treatment=[immediate=[VLAN_POP:unknown, OUTPUT:128]]
    ADDED, bytes=0, packets=0, table=1, priority=1000, selector=[IN_PORT:128, VLAN_VID:128], treatment=[immediate=[VLAN_PUSH:vlan, VLAN_ID:1000, OUTPUT:0]]
```

Before starting the IGMP test, execute the 'groups' command within ONOS to verify that no groups have been created.

```shell
groups
```

Now let's send an IGMP packet from the RG up the ONU. To do this run the following in the RG container.

```shell
igmp.py -j -i ens9f1 -m 229.0.0.1
```

this will return

```shell
.
Sent 1 packets.
```

which indicates that one igmp packet has been sent.

Let us now check the state in ONOS, starting with the group information. Run the following in the ONOS prompt.

```shell
groups
```

which returns

```shell
deviceId=of:0000000000000001, groupCount=1
   id=0x1, state=ADDED, type=ALL, bytes=0, packets=0, appId=org.onosproject.cordmcast
   id=0x1, bucket=1, bytes=0, packets=0, actions=[VLAN_POP:unknown, OUTPUT:128]
```

This shows that the a group was installed that forward packets to the ONU which sent the igmp.

For a group to be useful a flow must point to this group. So let's check in ONOS whether a flow exists.

```shell
flows -s
```

and find a flow which looks like

```shell
ADDED, bytes=0, packets=0, table=0, priority=500, selector=[IN_PORT:0, ETH_TYPE:ipv4, VLAN_VID:140, IPV4_DST:229.0.0.1/32], treatment=[immediate=[GROUP:0x1]]
```

This indicates that a multicast traffic with destination ip 229.0.0.1 should be handled by group 1.

Now let's check whether we find this state in the logical device in VOLTHA. Let's run the following in the VOLTHA CLI.

```shell
logical_device
flows
```

which will return

```shell
Logical Device 1 (type: n/a)
Flows (10):
+----------+----------+-----------+---------+----------+----------+----------+-----------+---------+---------+----------+--------------+----------+-----------+-------+------------+------------+
| table_id | priority |    cookie | in_port | vlan_vid | eth_type | ip_proto |  ipv4_dst | udp_src | udp_dst | metadata | set_vlan_vid | pop_vlan | push_vlan | group |     output | goto-table |
+----------+----------+-----------+---------+----------+----------+----------+-----------+---------+---------+----------+--------------+----------+-----------+-------+------------+------------+
|        0 |     1000 | 242068... |     128 |          |     888E |          |           |         |         |          |              |          |           |       | CONTROLLER |            |
|        0 |     1000 | 242068... |     129 |          |     888E |          |           |         |         |          |              |          |           |       | CONTROLLER |            |
|        0 |     1000 | 242068... |     130 |          |     888E |          |           |         |         |          |              |          |           |       | CONTROLLER |            |
|        0 |    10000 | 242068... |     128 |          |      800 |        2 |           |         |         |          |              |          |           |       | CONTROLLER |            |
|        1 |     1000 | 242068... |       0 |      128 |          |          |           |         |         |          |              |      Yes |           |       |        128 |            |
|        0 |     1000 | 242068... |       0 |     1000 |          |          |           |         |         |      128 |              |      Yes |           |       |            |          1 |
|        1 |     1000 | 242068... |     128 |      128 |          |          |           |         |         |          |         1000 |          |      8100 |       |          0 |            |
|        0 |     1000 | 242068... |     128 |        0 |          |          |           |         |         |          |          128 |          |           |       |            |          1 |
|        0 |     1000 | 242068... |     128 |          |      800 |       17 |           |      68 |      67 |          |              |          |           |       | CONTROLLER |            |
|        0 |      500 | 267401... |       0 |      140 |      800 |          | 229.0.0.1 |         |         |          |              |          |           |     1 |            |            |
+----------+----------+-----------+---------+----------+----------+----------+-----------+---------+---------+----------+--------------+----------+-----------+-------+------------+------------+
```

and we can see a rule with 229.0.0.1 which point to group 1.

Let's now look at the physical device level. Still in the Voltha CLI run the following.

```shell
devices
```

this returns

```shell
Devices:
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
|           id |       type | root |    parent_id | vlan | admin_state | oper_status | connect_status | parent_port_no |    host_and_port | proxy_address.device_id | proxy_address.channel_id |
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
| dece8e843be5 | ponsim_olt | True |            1 |      |     ENABLED |      ACTIVE |      REACHABLE |                | 172.17.0.1:50060 |                         |                          |
| 56a6fc8b859f | ponsim_onu | True | dece8e843be5 |  128 |     ENABLED |      ACTIVE |      REACHABLE |              1 |                  |            dece8e843be5 |                      128 |
| b40cae50dcf7 | ponsim_onu | True | dece8e843be5 |  129 |     ENABLED |      ACTIVE |      REACHABLE |              1 |                  |            dece8e843be5 |                      129 |
| d47b951c3fd2 | ponsim_onu | True | dece8e843be5 |  130 |     ENABLED |      ACTIVE |      REACHABLE |              1 |                  |            dece8e843be5 |                      130 |
+--------------+------------+------+--------------+------+-------------+-------------+----------------+----------------+------------------+-------------------------+--------------------------+
```

Identify the ONU which sent the IGMP packet (128) and copy its device id (56a6fc8b859f in this case). Next run the following in the Voltha CLI.

```shell
device 56a6fc8b859f
flows
```

which returns

```shell
Device 56a6fc8b859f (type: ponsim_onu)
Flows (6):
+----------+----------+-----------+---------+----------+----------+-----------+--------------+----------+-----------+--------+
| table_id | priority |    cookie | in_port | vlan_vid | eth_type |  ipv4_dst | set_vlan_vid | pop_vlan | push_vlan | output |
+----------+----------+-----------+---------+----------+----------+-----------+--------------+----------+-----------+--------+
|        0 |      500 |         0 |       2 |        0 |          |           |          128 |          |           |      1 |
|        0 |      500 |         0 |       2 | untagged |          |           |          128 |          |      8100 |      1 |
|        0 |      500 |         0 |       1 |      128 |          |           |            0 |          |           |      2 |
|        0 |     1000 | 242068... |       1 |      128 |          |           |              |      Yes |           |      2 |
|        0 |     1000 | 242068... |       2 |        0 |          |           |          128 |          |           |      1 |
|        0 |      500 | 267401... |       1 |          |      800 | 229.0.0.1 |              |          |           |      2 |
+----------+----------+-----------+---------+----------+----------+-----------+--------------+----------+-----------+--------+
```

And we can see that 229.0.0.1 outputs the packet to the right port.

Let us now try this out for real with a real packet. Let's first build a multicast frame on the server and send it down the nni port to the OLT, we can do this with scapy.

```shell
sudo scapy
mc = Ether(src="00:00:00:00:00:01")/Dot1Q(vlan=140)/IP(dst="229.0.0.1", proto=17)
sendp(mc, iface="ens9f0")
```

Meanwhile run tcpdump in the RG container:

```shell
tcpdump -nei ens9f1
```

in he RG container while tcpdump'ing we should see the following output.

```shell
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eno2.2021, link-type EN10MB (Ethernet), capture size 262144 bytes
08:09:43.004776 00:00:00:00:00:01 > 01:00:5e:00:00:01, ethertype IPv4 (0x0800), length 34: 10.0.2.15 > 229.0.0.1: [|udp]
```

Woohoo!

## Pass/Fail Criteria

* Flows and groups installed in ONOS
* Flows and groups installed in Voltha
* Multicast packet forwarded down to the correct ONU port.
