# ONU PM Metrics


**THESE ARE PRELIMINARY METRIC GROUPS**, Work is needed by the VOLTHA community to reach a consensus on the
actual metrics that will be provided.  **Also**, please read the **Remaining Work Item** sections of each
README file.


This document outlines the non-interval metrics collected for the ONU by the OpenOMCI code.  These
are primarily collected from one of the many OMCI Managed Entities

## Format on the Kafka bus

The format of the ONU KPI Events is detailed in the [Basic KPI Format (**KpiEvent2**)](../README.md)
section of this documents parent directory for wire format on the bus. This document primarily provides
the group metric information for OLT PKIs and associated metadata context information.

**All** metric values reported by the library are reported as *float*s. The context and metric tables
listed in the sections below report the type as initially collected by the OLT Device Adapters.

#ONU PM Metric Groups

The following sections outline the KPI metrics gathered by OpenOMCI on behalf of the ONU. If an ONU
does not support a specific metric in a group, it will not report that metric. This is preferred to
reporting a metric and it always having a value of 0.0 (which could be misleading).

**Note**: Currently all metric groups are collected and reported at one time (only one collection timer)
and this value is controlled by the VOLTHA shared kpi library's PM_Config default_freq value and will
be set to _60 seconds_. This single-collection deficiency will be corrected in the near future. 

## ANI Optical KPI Metrics

This group reports the ONU's Optical Power metrics for each PON physical port as reported by the
OMCI Managed Entity ANI-G (_Class ID #263_).

**Metric Group Name**: PON_Optical 
**Default Collection**: True  
**Default Interval**:  15 minutes

**Metadata Context items**

| key     | value   | Notes |
| :-----: | :------ | :---- |
| intf_id | integer | Physical device interface port ID for this PON/ANI port |

The port ID is extracted from the lower 8-bits of the ANI-G Managed Entity ID and indicates
the physical position of the PON interface.

**Metrics**

| key                     | type / size  | Notes |
| :---------------------: | :----------- | :---- |
| transmit_power          | int, 16-bits | This attribute reports the current measurement of mean optical launch power. Its value is a 2s complement integer referred to 1 mW (i.e., dBm), with 0.002 dB granularity |
| receive_power           | int, 16-bits | This attribute reports the current measurement of the total downstream optical signal level. Its value is a 2s complement integer referred to 1 mW (i.e., dBm), with 0.002 dB granularity. |

**NOTE**: The following metrics were also requested for the PON interface in
[VOL-935](https://jira.opencord.org/browse/VOL-935) but they are not available through
the OpenOMCI set of Managed Entities. However there are alarms available that relate to
these items available through the ANI-G ME:

 - ONT Optical module/transceiver temperature
 - ONT Optical module/transceiver voltage
 - ONT Laser bias current
 
TR-287 does reference mechanisms to perform OLT and ONU Optical Link monitoring to cover these
three items but interfaces are not yet available in VOLTHA and retrieval of these values from
an ONU may be difficult as the only defined interface to retrieve data is OMCI.

## UNI KPI Metrics

This group reports metrics associated with the customer facing UNI port of the ONU
and is collected from OMCI Physical Path Termination Point Ethernet UNI (_Class ID #11_)
and the UNI-G (_Class iD #264_).

**Metric Group Name**: UNI_Status
**Default Collection**: True  
**Default Interval**:  15 minutes

**Metadata Context items**

| key     | value   | Notes |
| :-----: | :------ | :---- |
| intf_id | integer | Physical device interface port ID for this UNI port |

The port ID is extracted from the UNI-G Managed Entity ID and indicates the 
physical position of the UNI interface.  This ID is implicitly linked to the
associated PPTP Ethernet UNI ME.

**Metrics**

| key              | type / size | From  | Notes |
| :--------------: | :---------- | :---- | :---- |
| ethernet_type    | int, gauge  | PPTP  | This attribute represents the sensed interface type as defined in the table below |
| oper_status      | boolean     | PPTP  | Link status/Operational Status: Link up (1), Link down (0) |
| pptp_admin_state | boolean     | PPTP  | Administrative state: Locked/disabled (1), Unlocked/enabled (0) |
| uni_admin_state  | boolean     | UNI-G | Administrative state: Locked/disabled (1), Unlocked/enabled (0) |

**Sensed Ethernet Type Table**

| value | Rate             | Duplex |
| ----: | :--------------: | :--- |
|  0x00 | Unknown          | n/a  |
|  0x01 | 10BASE-T         | full |
|  0x02 | 100BASE-T        | full |
|  0x03 | Gigabit Ethernet | full |
|  0x04 | 10Gb/s Ethernet  | full |
|  0x05 | 2.5Gb/s Ethernet | full |
|  0x06 | 5Gb/s Ethernet   | full |
|  0x07 | 25Gb/s Ethernet  | full |
|  0x08 | 40Gb/s  Ethernet | full |
|  0x11 | 10BASE-T         | half |
|  0x12 | 100BASE-T        | half |
|  0x13 | Gigabit Ethernet | half |

# Remaining Work Items

This initial code is only a preliminary work. See the [Remaining Work Items](../README.md)
section of this document's parent directory for a list of remaining tasks. In addition to these
work items, the interval statistics [README](./IntervalMetrics.md) may have additional work
items remaining.


TODO: For each group, list if the default is enabled/disabled