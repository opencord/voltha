# M3 - Manually Install EAPOL Forwarding Flows

## Test Objective

* Use Voltha CLI to manually download EAPOL forwarding rule to PON network

## Test Configuration

* TBF

## Test Procedure

### Step 1: If not yet running, launch Voltha CLI

```shell
cd $VOLTHA_BASE
./cli/main.py -L
```
(Note, the *-L* option is needed if Voltha was launched as a container using docker-compose.)

### Step 2: Note the device ID

Note the Voltha logical device ID of the PON network being tested.
If in doubt, use the following Voltha CLI command to list all devices:

```shell
devices
```

The output may be something like this (lines are truncated):

```shell
(voltha) devices
Devices:
+--------------+---------------+------+--------------+------+--------------...
|           id |          type | root |    parent_id | vlan |       mac_add...
+--------------+---------------+------+--------------+------+--------------...
| 25dadc44a847 |     maple_olt | True |            1 |      | 00:0c:e2:31:4...
| d178c7a3b07b |  broadcom_onu |      | 25dadc44a847 |  101 |              ...
+--------------+---------------+------+--------------+------+--------------...
```

In this case the OLT's device id was *25dadc44a847* and the logical device id shown as the parent_id for the OLT. In this case the logical device id is *1*.

### Step 3: Download EAPOL forwarding rules to the PON

Using the test mode of the CLI, download the rules:

```shell
test
install_eapol_flow 1
```

where you must use the logical device ID. The CLI provides TAB completion that can help too.

## Pass/Fail Criteria

[Zsolt to finish]
