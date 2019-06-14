
### matching-onu-port-label-invalid

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

### rx-in-invalid-state

This happens after olt is rebooted.

```
64988 20190419T230147.166 ERROR    MainThread mib_sync.on_set_response {'instance_id': 'vcore-0_1555714355', 'vcore_id': '0001', '      state': 'uploading', 'event': 'rx-in-invalid-state', 'device_id': '0001f9e07f8ee9e3'}
```

### Eapol flow not added after olt reboot

20190419T234544.680 DEBUG    MainThread openolt_flow_mgr.add_eapol_flow {'instance_id': 'vcore-0_1555716854', 'ip': '10.90.0.122:9191', 'event': 'flow-exists--not-re-adding', 'vcore_id': '0001'}

### coordinator_etcd._retry

Happens at startup
```
20190420T012854.182 ERROR    MainThread coordinator_etcd._retry {'instance_id': 'vcore-0', 'exception': 'Traceback (most recent call last):\n  File "/voltha/voltha/coordinator_etcd.py", line 564, in _retry\n    result = yield operation(*args, **kw)\nConnectionRefusedError: Connection was refused by other side: 111: Connection refused.', 'event': ConnectionRefusedError('Connection refused',)}
```

### coordinator_etcd._get

Happens at startup
```
20190420T012915.020 ERROR    MainThread coordinator_etcd._get {'instance_id': 'vcore-0', 'exception': 'Traceback (most recent call last):\n  File "/voltha/voltha/coordinator_etcd.py", line 605, in _get\n    (index, result) = yield self._retry(\'GET\', key, **kw)\n  File "/usr/local/lib/python2.7/dist-packages/twisted/internet/defer.py", line 1386, in _inlineCallbacks\n    result = g.send(result)\n  File "/voltha/voltha/coordinator_etcd.py", line 577, in _retry\n    returnValue(result)\nUnboundLocalError: local variable \'result\' referenced before assignment', 'e': UnboundLocalError("local variable 'result' referenced before assignment",), 'event': 'got-exception'}
```
