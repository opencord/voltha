# T5 - Verify unicast traffic flow

## Test Objective

* Purpose of this test is to verify that unicast traffic flows through the system
    * Correct Tibit PON environment
    * Logical device visible in VOLTHA cli

## Test Configuration

* VOLTHA ensemble running as per [deployment instructions](V01_voltha_bringup_deploy.md).
* Tibit OLT and ONUs registered as ACTIVE in VOLTHA

## Test Procedure

Execute the following command from the RG side

```shell
ping -I ens9f1 1.2.3.4
```

Meanwhile tcpdump on the VOLTHA server.

```shell
sudo tcpdump -nei ens9f0
```

which will output

```shell
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on pon1_0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:53:44.328260 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
13:53:45.322475 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
13:53:46.322725 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
13:53:47.325610 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
13:53:48.322729 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
13:53:49.322517 06:0c:49:94:35:7e > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 50: vlan 1000, p 0, ethertype 802.1Q, vlan 128, p 0, ethertype ARP, Request who-has 1.2.3.4 tell 10.1.11.63, length 28
```

## Pass/Fail Criteria

Ping completes successfully
