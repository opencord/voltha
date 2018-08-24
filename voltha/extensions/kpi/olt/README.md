# OLT PM Metrics


**THESE ARE PRELIMINARY METRIC GROUPS**, Work is needed by the VOLTHA community to reach a consensus on the
actual metrics that will be provided. **Also**, please read the **Remaining Work Item** sections of each
README file.



This document outlines the metrics reported by VOLTHA OLTs.  These are currently collected
from OLT Device Adapter which is responsible for polling the hardware for information. A future
version of the Performance Monitoring Library will allow for collection on-demand.

## Format on the Kafka bus

The format of the OLT KPI Events is detailed in the [Basic KPI Format (**KpiEvent2**)](../README.md)
section of this documents parent directory for wire format on the bus. This document primarily provides
the group metric information for OLT PKIs and associated metadata context information.

**All** metric values reported by the library are reported as *float*s. The context and metric tables
listed in the sections below report the type as initially collected by the OLT Device Adapters.

#OLT PM Metric Groups

The following sections outline the KPI metrics gathered by most OLT Device adapters. If an OLT does not
support a specific metric in a group, it will not report that metric. This is preferred to reporting a
metric and it always having a value of 0.0 (which could be misleading).

## Admin and Oper State/status

Various interfaces will provide a numeric (integer) value for the current Admin State and Operation
Status of the interface.  These map to the following states:

**Admin State**

| State             | Value | Notes |
| ----------------: | :---: | :---- |
| UNKNOWN           |   0   | The administrative state of the device is unknown |
| DISABLED          |   2   | The device is disabled and shall not perform its intended forwarding functions other than being available for re-activation. |
| PREPROVISIONED    |   1   | The device is pre-provisioned into Voltha, but not contacted by it |
| ENABLED           |   3   | The device is enabled for activation and operation |
| DOWNLOADING_IMAGE |   4   | The device is in the state of image download |

**Operational Status**

| State      | Value | Notes |
| ---------: | :---: | :---- |
| UNKNOWN    |   0   | The status of the device is unknown at this point |
| DISCOVERED |   1   | The device has been discovered, but not yet activated |
| ACTIVATING |   2   | The device is being activated (booted, rebooted, upgraded, etc.) |
| TESTING    |   3   | Service impacting tests are being conducted |
| ACTIVE     |   4   | The device is up and active |
| FAILED     |   5   | The device has failed and cannot fulfill its intended role |

## NNI KPI Metrics

This metric provides metrics for a specific NNI Port of an OLT

**Metadata Context items**

| key         | value   | Notes |
| :---------: | :------ | :---- |
| intf_id     | integer | Physical device interface port number for this NNI port |

**Metrics**

| key              | type / size  | Notes |
| :--------------: | :----------- | :---- |
| admin_state      | state        | See _Admin State_ section above |
| oper_status      | state        | See _Operational Status_ section above |
| rx_bytes         | int, 64-bits | TODO: add definition here... |
| rx_packets       | int, 64-bits | TODO: add definition here... |
| rx_ucast_packets | int, 64-bits | TODO: add definition here... |
| rx_mcast_packets | int, 64-bits | TODO: add definition here... |
| rx_bcast_packets | int, 64-bits | TODO: add definition here... |
| rx_error_packets | int, 64-bits | TODO: add definition here... | 
| tx_bytes         | int, 64-bits | TODO: add definition here... |
| tx_packets       | int, 64-bits | TODO: add definition here... |
| tx_ucast_packets | int, 64-bits | TODO: add definition here... |
| tx_mcast_packets | int, 64-bits | TODO: add definition here... |
| tx_bcast_packets | int, 64-bits | TODO: add definition here... |
| tx_error_packets | int, 64-bits | TODO: add definition here... |
| rx_crc_errors    | int, 64-bits | TODO: add definition here... |
| bip_errors       | int, 64-bits | TODO: add definition here... |

## PON KPI Metrics

The OLT PON Port metrics

**Metadata Context items**

| key         | value   | Notes |
| :---------: | :------ | :---- |
| intf_id     | integer | Physical device interface port number for this NNI port |
| pon_id      | integer | PON ID (0..n) |

**Metrics**

| key                  | type / size  | Notes |
| :------------------: | :----------- | :---- |
| admin_state          | state        | See _Admin State_ section above |
| oper_status          | state        | See _Operational Status_ section above |
| rx_packets           | int, 64-bits | Sum of all the RX Packets of GEM ports that are not base TCONT's |
| rx_bytes             | int, 64-bits | Sum of all the RX Octets of GEM ports that are not base TCONT's |
| tx_packets           | int, 64-bits | Sum of all the TX Packets of GEM ports that are not base TCONT's |
| tx_bytes             | int, 64-bits | Sum of all the TX Octets of GEM ports that are not base TCONT's |
| tx_bip_errors        | int, 32-bits | Sum of all the TX ONU bip errors to get TX BIP's per PON |
| in_service_onus      | int          | The number of activated ONUs on this pon |
| closest_onu_distance | float        | Distance to the closest ONU, units=kM w/granularity in the thousandths |

## ONU KPI Metrics

The OLT metrics for each activated ONUs

**Metadata Context items**

| key         | value   | Notes |
| :---------: | :------ | :---- |
| intf_id     | integer | Physical device interface port number for this NNI port |
| pon_id      | integer | PON ID (0..n) |
| onu_id      | integer | ONU ID |

**Metrics**

| key                | type / size  | Notes |
| :----------------: | :----------- | :---- |
| fiber_length       | float        | Distance to ONU, units=kM w/granularity in the thousandths |
| equalization_delay | int, 32-bits | Equalization delay |
| rssi               | int, 32-bits | The received signal strength indication of the ONU. |

**TODO**: How about the following as well?
 - rx_packets - int, 32-bits - Rx packets received on all GEM ports
 - rx_bytes   - int, 64-bits - Rx octets received on all GEM ports
 - tx_packets - int, 32-bits - Tx packets transmitted on all GEM ports
 - tx_bytes   - int, 64-bits - Rx packets transmitted on all GEM ports
 - tx_bip_errors - int, 32-bits - Sum of all the TX ONU bip errors to get TX BIP's on all GEM ports

## GEM Port KPI Metrics

The GEM Port metrics for each activated ONUs

**Metadata Context items**

| key         | value   | Notes |
| :---------: | :------ | :---- |
| intf_id     | integer | Physical device interface port number for this NNI port |
| pon_id      | integer | PON ID (0..n) |
| onu_id      | integer | ONU ID |
| gem_id      | integer | GEM Port ID |

**Metrics**

| key         | type / size  | Notes |
| :---------: | :----------- | :---- |
| alloc_id    | int, 16-bits | TODO: add definition here... |
| rx_packets  | int, 32-bits | Rx packets received |
| rx_bytes    | int, 64-bits | Rx octets received |
| tx_packets  | int, 32-bits | Tx packets transmitted |
| tx_bytes    | int, 64-bits | Rx packets transmitted |

# Remaining Work Items

This initial code is only a preliminary work. See the [Remaining Work Items](../README.md)
section of this document's parent directory for a list of remaining tasks. 
  
- [VOL-932](https://jira.opencord.org/browse/VOL-932) PM Interval collection on the OLT. Need
  to consult OLT device adapter vendors and operators for which KPIs would best fit in the
  interval groups. Intervals differ from other metric groups as they are defined to collect on
  a specific interval (15-minutes most common) and at the start of the interval, the counters
  should be set to zero so that the accumulation during the interval is what is reported. See
  also [VOL-933](https://jira.opencord.org/browse/VOL-932),
       [VOL-934](https://jira.opencord.org/browse/VOL-934),
       [VOL-935](https://jira.opencord.org/browse/VOL-935),
       [VOL-938](https://jira.opencord.org/browse/VOL-938),
       [VOL-939](https://jira.opencord.org/browse/VOL-939),
       [VOL-940](https://jira.opencord.org/browse/VOL-940).
       **NOTE**: A couple of the ones above are for the ONU

TODO: For each group, list if the default is enabled/disabled