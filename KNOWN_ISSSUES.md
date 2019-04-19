
### `matching-onu-port-label-invalid` error
This happens after olt is rebooted.

```
20190419T230010.719 ERROR    MainThread openolt_data_model.__onu_ports_down {'onu_port_id': 'PON port', 'onu_ports': [port_no: 100
label: "PON port"
type: PON_ONU
admin_state: DISABLED
device_id: "0001f2c9e5b98ce4"
peers {
  device_id: "00010d5c85383648"
  port_no: 16
}
, port_no: 16
label: "uni-16"
type: ETHERNET_UNI
admin_state: DISABLED
device_id: "0001f2c9e5b98ce4"
], 'vcore_id': '0001', 'error': KeyError('key id=PON port not found',), 'instance_id': 'vcore-0_1555714355', 'olt_id': '00010d5c85383648', 'onu_id': '0001f2c9e5b98ce4', 'event': 'matching-onu-port-label-invalid'}
20190419T230010.720 DEBUG    MainThread openolt_data_model.__onu_ports_down {'instance_id': 'vcore-0_1555714355', 'vcore_id': '0001', 'event': 'onu-ports-down', 'onu_port': port_no: 16
label: "uni-16"
type: ETHERNET_UNI
admin_state: DISABLED
device_id: "0001f2c9e5b98ce4"
}
```

### `rx-in-invalid-state` error message in mib_sync.on_set_response
This happens after olt is rebooted.

```
64988 20190419T230147.166 ERROR    MainThread mib_sync.on_set_response {'instance_id': 'vcore-0_1555714355', 'vcore_id': '0001', '      state': 'uploading', 'event': 'rx-in-invalid-state', 'device_id': '0001f9e07f8ee9e3'}
```

### Eapol flow not added after olt reboot

20190419T234544.680 DEBUG    MainThread openolt_flow_mgr.add_eapol_flow {'instance_id': 'vcore-0_1555716854', 'ip': '10.90.0.122:9191', 'event': 'flow-exists--not-re-adding', 'vcore_id': '0001'}
