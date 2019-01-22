# OpenOLT Device Adapter

## Enable OpenOLT
To preprovision and enable the OpenOLT use the below commands from the Voltha CLI. 
```bash
    (voltha) preprovision_olt -t openolt -H YOUR_OLT_MGMT_IP:9191
    (voltha) enable
```

### Additional Notes
1. The `bal_core_dist` and openolt driver should be running on the OLT device, before enabling the device from VOLTHA CLI.
2. 9191 is the TCP port that the OpenOLT driver uses for its gRPC channel
3. In the commands above, you can either use the loopback IP address (127.0.0.1) or substitute all its occurrences with the management IP of your OLT 

## Using Resource Manager with Open OLT adapter
Resource Manager is used to manage device PON resource pool and allocate PON resources
from such pools. Resource Manager module currently manages assignment of ONU-ID, ALLOC-ID and GEM-PORT ID.
The Resource Manager uses the KV store to back-up all the resource pool allocation data.

The OpenOLT adapter interacts with Resource Manager module for PON resource assignments.
The `openolt_resource_manager` module is responsible for interfacing with the Resource Manager.

The Resource Manager optionally uses `olt_model_type` specific resource ranges to initialize the PON resource pools.
In order to utilize this option, create an entry for `olt_model_type` specific PON resource ranges on the KV store.
Please make sure to use the same KV store used by the VOLTHA core.

### For example
To specify ASFvOLT16 OLT device specific resource ranges, first create a JSON file `asfvolt16_resource_range.json` with the following entry
```bash
{
    "onu_id_start": 1,
    "onu_id_end": 127,
    "alloc_id_start": 1024,
    "alloc_id_end": 2816,
    "gemport_id_start": 1024,
    "gemport_id_end": 8960,
    "pon_ports": 16
}
```
This data should be put on the KV store location `resource_manager/xgspon/resource_ranges/asfvolt16`

The format of the KV store location is `resource_manager/<technology>/resource_ranges/<olt_model_type>` 

In the below example the KV store is assumed to be Consul. However the same is applicable to be etcd or any other KV store.
Please make sure to use the same KV store used by the VOLTHA core.
```bash
curl -X PUT -H "Content-Type: application/json" http://127.0.0.1:8500/v1/kv/resource_manager/xgspon/resource_ranges/asfvolt16 -d @./asfvolt16_resource_range.json 
```

The `olt_model_type` should be referred to during the preprovisiong step as shown below. The `olt_model_type` is an extra option and
should be specified after `--`. The `--olt_model or -o` specifies the `olt_model_type`. The olt_model_type is also learned
from the physical device when connecting and the value from the preprovisioning command is optional to override the model
information learned from the device.

```bash
 (voltha) preprovision_olt -t openolt -H 192.168.50.100:9191 -- -o asfvolt16
```

Once the OLT device is enabled, any further PON Resource assignments will happen within the PON Resource ranges defined
in `asfvolt16_resource_range.json` and placed on the KV store.

#### Additional Notes
If a `default` resource range profile should be used with all `olt_model_type`s, then place such Resource Range profile
at the below path on the KV store. 
```bash
resource_manager/xgspon/resource_ranges/default
```
