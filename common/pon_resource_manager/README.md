# Resource Manager Profile Configuration

Resource Manager module is responsible for managing PON resource pools.
It exposes APIs to allocate/free the following resources from the Resource Pools.
1) alloc_ids
2) onu_ids
3) gemport_ids
4) flow_ids
5) uni_port_ids.

Resource Manager uses a KV store in backend to ensure resiliency of the Resource Pool data.
## Configuring Resource Ranges
Resource Manager assumes the following defaults when no explicit configuration is available
```
    {
        "onu_id_start": 1,
        "onu_id_end": 127,
        "alloc_id_start": 1024,
        "alloc_id_end": 2816,
        "gemport_id_start": 1024,
        "gemport_id_end": 8960,
        "flow_id_start": 1,
        "flow_id_end": 16383,
        "uni_id_start": 0,
        "uni_id_end": 0,
        "pon_ports": 16
    }
```
To configure specific Resource Ranges for a given OLT model, place the Resource Range JSON at the below path on the KV store and specify the OLT model at the time of OLT pre-provision step.

```
service/voltha/resource_manager/<technology>/resource_ranges/<olt_model>
```

Example KV path is `service/voltha/resource_manager/xgpon/resource_ranges/asfvolt16`

Create a ResourceRanges.json file with the example content as below.

```
    {
        "onu_id_start": 1,
        "onu_id_end": 127,
        "alloc_id_start": 1024,
        "alloc_id_end": 2816,
        "gemport_id_start": 1024,
        "gemport_id_end": 8960,
        "flow_id_start": 1,
        "flow_id_end": 16383,
        "uni_id_start": 0,
        "uni_id_end": 0,
        "pon_ports": 16
    }
```

Assuming etcd is the KV store in use, push the ResourceRange using below command.
```
curl -sSL -XPUT http://<etcd-ip>:2379/v2/keys/service/voltha/resource_manager/xgpon/resource_ranges/asfvolt16 -d value="$(jq -c . ResourceRanges.json)"
```

When the OLT is being pre-provisioned, specify the OLT model. The Resource Manager will use this OLT model  to look up on the KV store to find any available Resource Range profile and initialize the Resource Pools accordingly. The `-m` below specifies the OLT Model.

```
preprovision_olt -t openolt -H 192.168.50.100:9191 -m asfvolt16
```

`Note:` In case of OpenOLT device, resource ranges (if queried and available from the device), will override the resource ranges read from the KV store.
