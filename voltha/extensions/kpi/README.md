# VOLTHA Performance Monitoring/KPI Library

This directory provides a common library for the creation of Performance Monitoring groups
within VOLTHA and should be used to insure that KPI information from different adapters use
the same format

## KPI Manager Creation

Currently, each device adapter is required to follow the following steps to create and
register PM Metric manager. This is typically performed in the device handler's
'activate' method (called in response to the device handler first being enabled)

1. Create an instance of a **AdapterPmMetrics** manager object. This is typically an
   **OltPmMetrics** object for an _OLT_ adapter, or an **OnuPmMetrics** adapter for an
   _ONU_ adapter. If you have additional device specific metrics to report, you can
   derive your own manager object from one of these two derived classes.
   
   This call takes a number of device adapter specific arguments and these are detailed
   in the pydoc headers for the managers _\_\_init___() method.
   
2. Create the ProtoBuf message for your metrics by calling the newly created _manager's_
   **_make_proto_**() method. 
   
3. Register the ProtoBuf message configuration with the adapter agent via the 
   _update_device_pm_config_() method with the optional init parameter set to **True**.
   
4. Request the manager to schedule the first PM collection interval by calling the
   manager's _start_collector_() method. You may wish to do this after a short pause
   depending on how your adapter is designed.
   
The next two subsections provides examples of these steps for both an OLT and an ONU
device adapter  

### OLT Device Adapters PM Manager setup

```python
    # Create the OLT PM Manager object
    kwargs = {
        'nni-ports': self.northbound_ports.values(),
        'pon-ports': self.southbound_ports.values()
    }
    self.pm_metrics = OltPmMetrics(self.adapter_agent, self.device_id,
                                   grouped=True, freq_override=False,
                                   **kwargs)

    # Create the protobuf message configuration
    pm_config = self.pm_metrics.make_proto()
    self.log.debug("initial-pm-config", pm_config=pm_config)
    
    # Create the PM information in the adapter agent
    self.adapter_agent.update_device_pm_config(pm_config, init=True)
        
    # Start collecting stats from the device after a brief pause
    reactor.callLater(10, self.pm_metrics.start_collector)
```

### ONU Device Adapters PM Manager setup

For ONU devices, if you wish to include OpenOMCI 15-minute historical interval
intervals, you will need to register the PM Metrics OpenOMCI Interval PM class
with OpenOMCI

```python

    # Create the OLT PM Manager object
    kwargs = {
        'heartbeat': self.heartbeat,
        'omci-cc': self.openomci.omci_cc
    }
    self.pm_metrics = OnuPmMetrics(self.adapter_agent, self.device_id,
                                   grouped=True, freq_override=False,
                                   **kwargs)
                                   
    # Create the protobuf message configuration
    pm_config = self.pm_metrics.make_proto()
    
    # Register the OMCI history intervals with OpenOMCI
    self.openomci.set_pm_config(self.pm_metrics.omci_pm.openomci_interval_pm)
    
    # Create the PM information in the adapter agent
    self.adapter_agent.update_device_pm_config(pm_config, init=True)
    
    # Start collecting stats from the device after a brief pause
    reactor.callLater(30, self.pm_metrics.start_collector)
```

# Basic KPI Format

**TODO**: This needs to be defined by the community with assistance from the _SEBA_
developers.

The KPI information is published on the kafka bus under the _voltha.kpi_ topic. For 
VOLTHA PM information, the kafka key is empty and the value is a JSON message composed
of the following key-value pairs.

| key      | value  | Notes |
| :-:      | :----- | :---- |
| type     | string | "slice" or "ts". A "slice" is a set of path/metric data for the same time-stamp. A "ts" is a time-series: array of data for same metric |
| ts       | float  | UTC time-stamp of data in slice mode (seconds since the epoch of January 1, 1970) |
| prefixes | list   | One or more prefixes.  A prefix is a key-value pair described below |

**NOTE**: The timestamp is currently retrieved as a whole value. It is also possible to easily get
the floating timestamp which contains the fractional seconds since epoch. **Is this of use**?

For group PM information, the key composed of a string with the following format:
```
    voltha.<device-adapter>.<device-id>.<group>[.<group-id>]
```
Here is an JSON **example** of a current KPI published on the kafka bus under the 
_voltha.kpi_ topic. In this case, the _device-adapter_ is the **adtran_olt**, the _device-id_ is
the value **0001c4397d43bc51**, the _group_ is **nni** port statistics, and the _group-id_ is the
port number is **1**.

```json
{
  "type": "slice",
  "ts": 1532379520.0,
  "prefixes": {
    "voltha.adtran_olt.0001c4397d43bc51.nni.1": {
      "metrics": {
        "tx_dropped": 0.0,
        "rx_packets": 0.0,
        "rx_bytes": 0.0,
        "rx_mcast": 0.0,
        "tx_mcast": 16.0,
        "rx_bcast": 0.0,
        "oper_status": 4.0,
        "admin_state": 3.0,
        "tx_bcast": 5639.0,
        "tx_bytes": 1997642.0,
        "rx_dropped": 0.0,
        "tx_packets": 5655.0,
        "port_no": 1.0,
        "rx_errors": 0.0
      }
    },
    "voltha.adtran_olt.0001c4397d43bc51.pon.0.onu.0": {
      "metrics": {
        "fiber_length": 29.0,
        "onu_id": 0.0,
        "pon_id": 0.0,
        "equalization_delay": 621376.0,
        "rssi": -167.0
      }
    },
    "voltha.adtran_olt.0001c4397d43bc51.pon.0.onu.1": {
      "metrics": {
        "fiber_length": 29.0,
        "onu_id": 1.0,
        "pon_id": 0.0,
        "equalization_delay": 621392.0,
        "rssi": -164.0
    },
    ...
              
    "voltha.adtran_olt.0001c4397d43bc51.pon.0.onu.0.gem.2176": {
      "metrics": {
        "rx_packets": 0.0,
        "rx_bytes": 0.0,
        "alloc_id": 1024.0,
        "gem_id": 2176.0,
        "pon_id": 0.0,
        "tx_bytes": 0.0,
        "onu_id": 0.0,
        "tx_packets": 0.0
      }
    },
    ...
  }
}

```

For OpenOMCI historical intervals, the name is derived from the Managed Entity class:

```json
{
  "type": "slice",
  "ts": 1532372864.0,
  "prefixes": {
    "voltha.adtran_onu.0001b8c505090b5b.EthernetFrameExtendedPerformanceMonitoring": {
      "metrics": {
        "entity_id": 2.0,
        "class_id": 334.0,
        "packets": 0.0,
        "octets": 0.0,
        "interval_end_time": 0.0,
        "crc_errored_packets": 0.0,
        "broadcast_packets": 0.0,
        "64_octets": 0.0,
        "65_to_127_octets": 0.0,
        "128_to_255_octets": 0.0,
        "256_to_511_octets": 0.0,
        "undersize_packets": 0.0,
        "drop_events": 0.0,
        "multicast_packets": 0.0,
        "oversize_packets": 0.0
      }
    }
  }
}
```
More information on the OpenOMCI ONU Historical Intervals is detailed in the _IntervalMetrics.md_
file in the _onu/_ subdirectory.

# Remaining Work Items

This initial code is only a preliminary sample. The following tasks need to be
added to the VOLTHA JIRA or performed in the SEBA group:
    
- Get a list from SEBA/VOLTHA on required metrics.

- Get feedback from other OLT/ONU developers on any needed changes

- Allow PM groups to have different collection times

- Support calling a 'get-data' method before collect the metrics.  Currently metrics are collected
  in a device adapter independent way and the PM just updates what the attributes happen to have.

- For statistics groups that have more than one instance, do we need to be able to
  enable/disable specific instances? Major refactor of code if so (database work, ...)

