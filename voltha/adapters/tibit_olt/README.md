# Developer notes:

Before auto-discovery is implemented, you can follow the steps below to activate a Tibit PON.
These steps assume:

* Voltha starts with fresh state (was just launched in single-instance mode)
* Tibit OLT and ONU(s) are powered on and properly connected with splitters.
* There is network reach from Voltha's host environment to the Tibit OLT via
  a specific interface of the host OS. We symbolically refer to this Linux
  interface as \<interface\>.
* All commands are to be executed from the root dir of the voltha project after
  env.sh was sourced, and at least 'make protos' was executed on the latest code.


## Step 1: Launch Voltha with the proper interface value.

```
./voltha/main.py -I <interface>  # example: ./voltha/main.py -I eth2
```

## Step 2: Launch Chameleon (in a different terminal)

```
./chamaleon/main.py
```

## Step 3: Verify Tibit adapters loaded

In a third terminal, issue the following RESt requests:

```
curl -s http://localhost:8881/api/v1/local/adapters | jq
```

This should list (among other entries) two entries for Tibit devices:
one for the Tibit OLT and one for the Tibit ONU.

The following request should show the device types supported:

```
curl -s http://localhost:8881/api/v1/local/device_types | jq
```

This should include two entries for Tibit devices, one for the OLT
and one for the ONU.

## Step 4: Pre-provision a Tibit OLT

Issue the following command to pre-provision the Tibit OLT:

```
curl -s -X POST -d '{"type": "tibit_olt", "mac_address": "00:0c:e2:31:06:00"}' \
    http://localhost:8881/api/v1/local/devices | jq '.' | tee olt.json
```

This shall return with a complete Device JSON object, including a 12-character
id of the new device and a preprovisioned state as admin state (it also saved the
json blob in a olt.json file):

```
{
  "vendor": "",
  "software_version": "",
  "parent_port_no": 0,
  "connect_status": "UNKNOWN",
  "root": false,
  "adapter": "tibit_olt",
  "vlan": 0,
  "hardware_version": "",
  "ports": [],
  "parent_id": "",
  "oper_status": "UNKNOWN",
  "admin_state": "PREPROVISIONED",
  "mac_address": "00:00:00:00:00:01",
  "serial_number": "",
  "model": "",
  "type": "tibit_olt",
  "id": "2db8e16804ec",
  "firmware_version": ""
}
```

For simplicity, store the device id as shell variable:

```
OLT_ID=$(jq .id olt.json | sed 's/"//g')
```

## Step 5: Activate the OLT

To activate the OLT, issue the following using the OLT_ID memorized above:

```
curl -s -X POST http://localhost:8881/api/v1/local/devices/$OLT_ID/activate
```

After this, if you retrieve the state of the OLT device, it should be enabled
and in the 'ACTIVATING' operational status:

```
curl http://localhost:8881/api/v1/local/devices/$OLT_ID | jq '.oper_status,.admin_state'
"ACTIVATING"
"ENABLED"
```
When the device is ACTIVE, the logical devices and logical ports should be created.  To check
the logical devices and logical ports, use the following commands.

```
curl -s http://localhost:8881/api/v1/local/logical_devices | jq '.'
# Note: Need to pull out logical device id.
curl -s http://localhost:8881/api/v1/local/logical_devices/47d2bb42a2c6/ports | jq '.'
```





# OLD stuff

[This will be moved to some other place soon.]

To get the EOAM stack to work with the ONOS olt-test, the following
command was used in the shell to launch the olt-test.

NOTE: This command should soon be eliminated as the adapter should
be started by VOLTHA. By running the commands as listed below, then
the olt-test can take advantage of the virtual environment.

```
$ cd <LOCATION_OF_VOLTHA>
$ sudo -s
# . ./env.sh
(venv-linux) # PYTHONPATH=$HOME/dev/voltha/voltha/adapters/tibit ./oftest/oft --test-dir=olt-oftest/ -i 1@enp1s0f0 -i 2@enp1s0f1 --port 6633 -V 1.3 -t "olt_port=1;onu_port=2;in_out_port=1;device_type='tibit'" olt-complex.TestScenario1SingleOnu
```
