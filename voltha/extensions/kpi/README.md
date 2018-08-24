# VOLTHA Performance Monitoring/KPI Library

This directory provides a common library for the creation of Performance Monitoring groups
within VOLTHA and should be used to insure that KPI information from different adapters use
the same format.

The original KpiEvent protobuf message is still supported for adapters that wish to use theprevious format but device adapter developers are encouraged to support the new format and
make use of this shared library. 

**Also**, please read the **Remaining Work Item** sections of each README.md file. Some additional
work items as well as existing/related JIRA items are highlighted in this section. 

## KPI Manager Creation

Currently, each device adapter is required to follow the following steps to create and
register PM Metric manager. This is typically performed in the device handler's
'activate' method (called in response to the device handler first being enabled)

1. Create an instance of a derived **AdapterPmMetrics** manager object. This is currently an
   **OltPmMetrics** object for an _OLT_ adapter, or an **OnuPmMetrics** adapter for an
   _ONU_ adapter. If you have additional device specific metrics to report, you can
   derive your own manager object from one of these two derived classes. In order to
   inherit (or modify) the metrics defined in those classes as well as support any new
   metrics specific to your device.
   
   This call takes a number of device adapter specific arguments and these are detailed
   in the pydoc headers for the appropriate  **AdapterPmMetrics** _\_\_init___() method.
   
2. Create the ProtoBuf message for your metrics by calling the newly created _manager's_
   **_make_proto_**() method. 
   
3. Register the ProtoBuf message configuration with the adapter agent via the 
   _update_device_pm_config_() method with the optional init parameter set to **True**.
   
4. Request the manager to schedule the first PM collection interval by calling the
   manager's _start_collector_() method. You may wish to do this after a short pause
   depending on how your adapter is designed.
   
**NOTE:** Currently there is only a single collection frequency for all metrics for
a given device adapter. In the future, individual collection intervals on a per-metric/metric-group
will be supported by the shared library.
   
The next two subsections provides examples of these steps for both an OLT and an ONU
device adapter  

### OLT Device Adapters PM Manager setup

```python
    # Create the OLT PM Manager object
    kwargs = {
        'nni-ports': self.northbound_ports.values(),
        'pon-ports': self.southbound_ports.values()
    }
    self.pm_metrics = OltPmMetrics(self.adapter_agent, self.device_id, self.logical_device_id,
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

### ONU Device Adapters PM Manager Setup

For ONU devices, if you wish to include OpenOMCI 15-minute historical interval
intervals, you will need to register the PM Metrics OpenOMCI Interval PM class
with OpenOMCI.  This ties in the OpenOMCI PM Interval State Machine with the KPI
shared library.

```python

    # Create the OLT PM Manager object
    kwargs = {
        'heartbeat': self.heartbeat,
        'omci-cc': self.openomci.omci_cc
    }
    self.pm_metrics = OnuPmMetrics(self.adapter_agent, self.device_id, self.logical_device_id,
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

### How metrics are currently collected

Currently, the default behaviour is to collect KPI information on a single periodic 
interval that can be adjusted via the NBI/CLI of VOLTHA.  It collects data by extracting
it from an object provided during the collection request and this object should either
provide attributes or a property method that matches the metric to be collected.
For instance, assume that you have an NNI metric called 'tx_packets'.  You would pass
an object during collection that should have one of the two following;

- a _tx_packets_ attribute/member name defined for the object that has the requested
  value already set (via background poll)
  
- a _tx_packets_ **property** method that accesses an internal variable with the value
  already set (via background poll) or that calculates/extracts the value without blockin
  the call.

### Known Issues in collection

Note that a future story will be created to allow for collection to be requested for
a metric/metric-group on demand so that background polling of KPI information is not
required for all reported metrics.

Note that a future story will be created to allow KPI information to be collected on
per-group/metric intervals.

# Basic KPI Format (**KpiEvent2**)

The KPI information is published on the kafka bus under the _voltha.kpi_ topic. For 
VOLTHA PM information, the kafka key is empty and the value is a JSON message composed
of the following key-value pairs.

| key        | value  | Notes |
| :--------: | :----- | :---- |
| type       | string | "slice" or "ts". A "slice" is a set of path/metric data for the same time-stamp. A "ts" is a time-series: array of data for same metric |
| ts         | float  | UTC time-stamp of when the KpiEvent2 was created (seconds since the epoch of January 1, 1970) |
| slice_data | list   | One or more sets of metrics composed of a _metadata_ section and a _metrics_ section. |

**NOTE**: Time-series metrics and corresponding protobuf messages have not been defined.

## Slice Data Format

For KPI slice KPI messages, the _slice_data_ portion of the **KpiEvent2** is composed of a _metadata_
section and a _metrics_ section.

### _metadata_ Section Format

The metadata section is used to:
 - Define which metric/metric-group is being reported (The _title_ field)
 - Provide some common fields required by all metrics (_title_, _timestamp_, _device ID_, ...)
 - Provide metric/metric-group specific context (the _context_ fields)

| key        | value  | Notes |
| :--------: | :----- | :---- |
| title       | string | "slice" or "ts". A "slice" is a set of path/metric data for the same time-stamp. A "ts" is a time-series: array of data for same metric |
| ts         | float | UTC time-stamp of data at the time of collection (seconds since the epoch of January 1, 1970) |
| logical_device_id | string | The logical ID that the device belongs to. This is equivalent to the DPID reported in ONOS for the VOLTHA logical device with the 'of:' prefix removed. |
| device_id | string | The physical device ID that is reporting the metric. |
| serial_number | string | The reported serial number for the physical device reporting the metric. |
| context | map | A key-value map of metric/metric-group specific information.|

The context map is composed of key-value pairs where the key (string) is the label for the context
specific value and the value (string) is the corresponding context value. While most values may be
better represented as a float/integer, there may be some that are better represented as text. For
this reason, values are always represented as strings to allow the ProtoBuf message format to be
as simple as possible.

Here is an JSON _example_ of a current KPI published on the kafka bus under the 
_voltha.kpi_ topic. 

```json
{
  "type": "slice",
  "ts": 1534440704.0,
  "slice_data": [
    {
      "metadata": {
        "title": "Ethernet",
        "ts": 1534440704.0,
        "logical_device_id": "000000139521a269",
        "device_id": "000115929ed71696",
        "serial_no": "dummy_sn2209199",
        "context": {
          "port_no": "1"
        }
      },
      "metrics": {
        "tx_dropped": 0.0,    # A COUNTER
        "rx_packets": 0.0,
        "rx_bytes": 0.0,
        "rx_mcast_packets": 0.0,
        "tx_mcast_packets": 16.0,
        "rx_bcast_packets": 0.0,
        "oper_status": 4.0,   # A STATE
        "admin_state": 3.0,
        "rx_errors": 0.0,
        "tx_bytes": 1436.0,
        "rx_dropped": 0.0,
        "tx_packets": 16.0,
        "tx_bcast": 0.0
      }
    },
    {
      "metadata": {
        "title": "PON",
        "logical_device_id": "000000139521a269",
        "device_id": "000115929ed71696",
        "serial_no": "dummy_sn2209199",
        "ts": 1534440704.0,
        "context": {
          "port_no": "5",
          "pon_id": "0"
        },
      },
      "metrics": {
        "rx_packets": 0.0,
        "in_service_onus": 0.0,     # A GAUGE
        "rx_bytes": 0.0,
        "closest_onu_distance": -1.0,
        "tx_bip_errors": 0.0,
        "oper_status": 4.0,
        "admin_state": 3.0,
        "tx_bytes": 0.0,
        "tx_packets": 0.0
      }
    },
    ...
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
    
- Get feedback from other OLT/ONU developers on any needed changes

- Allow PM groups to have different collection times

- Support calling a 'get-data' method before collect the metrics.  Currently metrics are collected
  in a device adapter independent way and the PM just updates what the attributes happen to have.
  This would provide an asynchronous request and upon successful completion, the KPI metric/group
  would be published on the Kafka bus.

- [VOL-931](https://jira.opencord.org/browse/VOL-931) Support for retrieval of PM measurements
  on-demaind. Would be best implemented after the previous async (get-data) work item.

- For statistics groups that have more than one instance, do we need to be able to
  enable/disable specific instances? Major refactor of code if so (database work, ...)

- [VOL-930](https://jira.opencord.org/browse/VOL-930) PM Collection Format. This format may
  fit better with the time-series KPI collection as it requests ability for start/stop times.
  It could possibly be done at a higher layer but the intent may be to have a greater number
  of samples on a specific metric instance for a defined period of time. Need clarification
  from the JIRA author.
