# ONU OMCI Historical Interval PM Groups

This document outlines the 15-minute interval groups currently supported by the
**OnuPmIntervalMetrics** _onu_pm_interval_metrics.py_ file.  These groups
cover a 15-minute interval.

## Performance Interval State Machine

At OpenOMCI startup within an ONU Device Adapter, as soon as the OpenOMCI ME database has
been declared to be in-sync ONU's ME Database, the Performance Interval State Machine is
started for the ONU. The first task it performs is to synchronize the ONU's (hardware) time with
the ONU Device Handler's (Linux container) so that a 15-minute interval is established.

The OpenOMCI PM interval state machine then examines managed elements created by the
ONU autonomously or created by OpenOMCI in response to a OMCI request from an ONU
adapter to determine if an appropriate 15-Minute historical PM ME needs to be attached. The
state machine also registers for notification of any create/delete requests at that
point so that it can add/remove 15-minute historical PM MEs as services are applied or
removed. 

Before adding a 15-minute historical PM ME, the ME capabilities of the ONU is
examined to insure that it can support that particular ME. This is important as the
Ethernet Frame historical intervals are actually supported by up to 4 different MEs
reporting the basically the same data. This is detailed below in the _Ethernet Frame
Performance Monitoring MEs_ section.

## Timezone

The ONU will be synchronized to the Linux Container running the ONU Device handler's
time in UTC upon startup. Not all ONUs have the capability to set their calendar 
date (month, day, year) to that of the ONU's Device Handler, but it will set the
clock to that date. For reporting of 15-minute intervals, only an accurate 15-minute
boundary is really of any great importance.

## Interval Reporting

After the ONU time synchronization request is made, the first reported interval is
schedule to occur in the next 15-minute boundry.  For example, if the OpenOMCI
state machine synchronizes the ONU's time at 

## Common Elements for All Reported MEs

In addition to counter elements (attributes) reported in each ME, every reported 
historical interval report the following Elements as context values in the KPI
Event metadata field.  Each value is reported as a _string_ per the Protobuf structure 
but are actually integer/floats.

| Label               | Type         | Description |
| ------------------: | :----------: | :---------- |
| class_id            | int, 16-bits | The ME Class ID of the PM Interval ME |
| entity_id           | int, 16-bits | The OMCI Entity Instance of the particular PM Interval ME |
| interval_end_time   | int, 8-bits  | Identifies the most recently finished 15 minute. This attribute is set to zero when a synchronize time request is performed by OpenOMCI.  This counter rolls over from 255 to 0 upon saturation. | 
| interval_start_time | int, 64-bits | The UTC timestamp (seconds since epoch) rounded down to the start time of the specific interval |

# Supported 15-Minute Historical Performance Monitoring MEs

The following 15-minute historical performance monitoring MEs currently supported are detailed
in the sections below

## Ethernet Frame Performance Monitoring MEs

The OMCI Ethernet PM supported by OpenOMCI includes 4 possible MEs.  These MEs are attached to
the MAC Bridge Port Configuration MEs for the ONU. For downstream data, the ME is placed on the
MAC Bridge Port Configuration ME closest to the ANI Port. For upstream data, the ME is placed
on the MAC Bridge Port Configuration ME closest to the associated UNI.

The OpenOMCI will first attempt to use the Extended Performance Monitoring MEs if they are
supported by the ONU.  First the 64-bit counter version will be attempted and then the 32-bit
counters as a fallback. If of the Extended Performance Monitoring MEs are supported, the
appropriate Upstream or DownStream Monitoring ME will be used.

### ME Information

The table below describes the four Ethernet Frame Performance Monitoring MEs and provides their
counter width (in bytes) and ME Class ID.

| ME Name                                                     | Class ID | Counter Width |
| ----------------------------------------------------------: | :------: | :---:   |
| Ethernet Frame Extended Performance Monitoring64Bit         |   426    |  64-bit |
| Ethernet Frame Extended Performance Monitoring              |   334    |  32-bit |
| Ethernet Frame Upstream Performance MonitoringHistoryData   |   322    |  32-bit |
| Ethernet Frame Downstream Performance MonitoringHistoryData |   321    |  32-bit |

**Metric Group Name**: Ethernet_Bridge_Port_History  
**Default Collection**: True  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Counter Information

Each of the Ethernet Frame PM MEs contain the following counters

| Attribute Name      | Description |
| ------------------: | :-----------|
| drop_events         | The total number of events in which packets were dropped due to a lack of resources. This is not necessarily the number of packets dropped; it is the number of times this event was detected. |
| octets              | The total number of upstream octets received, including those in bad packets, excluding framing bits, but including FCS. |
| packets             | The total number of upstream packets received, including bad packets, broadcast packets and multicast packets. |
| broadcast_packets   | The total number of upstream good packets received that were directed to the broadcast address. This does not include multicast packets. |
| multicast_packets   | The total number of upstream good packets received that were directed to a multicast address. This does not include broadcast packets. |
| crc_errored_packets | The total number of upstream packets received that had a length (excluding framing bits, but including FCS octets) of between 64 octets and 1518 octets, inclusive, but had either a bad FCS with an integral number of octets (FCS error) or a bad FCS with a non-integral number of octets (alignment error). |
| undersize_packets   | The total number of upstream packets received that were less than 64 octets long, but were otherwise well formed (excluding framing bits, but including FCS). |
| oversize_packets    | The total number of upstream packets received that were longer than 1518 octets (excluding framing bits, but including FCS) and were otherwise well formed. NOTE 2 – If 2 000 byte Ethernet frames are supported, counts in this performance parameter are not necessarily errors. |
| 64_octets           | The total number of upstream received packets (including bad packets) that were 64 octets long, excluding framing bits but including FCS. |
| 65_to_127_octets    | The total number of upstream received packets (including bad packets) that were 65..127 octets long, excluding framing bits but including FCS. |
| 128_to_255_octets   | The total number of upstream packets (including bad packets) received that were 128..255 octets long, excluding framing bits but including FCS. |
| 256_to_511_octets   | The total number of upstream packets (including bad packets) received that were 256..511 octets long, excluding framing bits but including FCS. |
| 512_to_1023_octets  | The total number of upstream packets (including bad packets) received that were 512..1 023 octets long, excluding framing bits but including FCS. |
| 1024_to_1518_octets | The total number of upstream packets (including bad packets) received that were 1024..1518 octets long, excluding framing bits, but including FCS. |

## Ethernet PM Monitoring History Data (Class ID 24)

This managed entity collects some of the performance monitoring data for a physical
Ethernet interface. Instances of this managed entity are created and deleted by the OLT.

**Metric Group Name**: Ethernet_UNI_History  
**Default Collection**: True  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Application

For performance monitoring of Ethernet UNI.

### Relationships

An instance of this managed entity is associated with an instance of the physical path
termination point Ethernet UNI.                 

### Attributes
All counters are 32-bits wide.

| Attribute Name      | Description |
| ------------------: | :-----------|
| fcs_errors                        | This attribute counts frames received on a particular interface that were an integral number of octets in length but failed the frame check sequence (FCS) check. The count is incremented when the MAC service returns the frameCheckError status to the link layer control (LLC) or other MAC user. Received frames for which multiple error conditions are obtained are counted according to the error status presented to the LLC. |
| excessive_collision_counter       | This attribute counts frames whose transmission failed due to excessive collisions. |
| late_collision_counter            | This attribute counts the number of times that a collision was detected later than 512 bit times into the transmission of a packet. |
| frames_too_long                   | This attribute counts received frames that exceeded the maximum permitted frame size. The count is incremented when the MAC service returns the frameTooLong status to the LLC. |
| buffer_overflows_on_rx            | This attribute counts the number of times that the receive buffer overflowed. |
| buffer_overflows_on_tx            | This attribute counts the number of times that the transmit buffer overflowed. |
| single_collision_frame_counter    | This attribute counts successfully transmitted frames whose transmission was delayed by exactly one collision. |
| multiple_collisions_frame_counter | This attribute counts successfully transmitted frames whose transmission was delayed by more than one collision. |
| sqe_counter                       | This attribute counts the number of times that the SQE test error message was generated by the PLS sublayer. |
| deferred_tx_counter               | This attribute counts frames whose first transmission attempt was delayed because the medium was busy. The count does not include frames involved in collisions. |
| internal_mac_tx_error_counter     | This attribute counts frames whose transmission failed due to an internal MAC sublayer transmit error. |
| carrier_sense_error_counter       | This attribute counts the number of times that carrier sense was lost or never asserted when attempting to transmit a frame. |
| alignment_error_counter           | This attribute counts received frames that were not an integral number of octets in length and did not pass the FCS check. |
| internal_mac_rx_error_counter     | This attribute counts frames whose reception failed due to an internal MAC sublayer receive error. |

## FEC Performance Monitoring History Data (Class ID 312)

This managed entity collects performance monitoring data associated with PON downstream FEC
counters. Instances of this managed entity are created and deleted by the OLT.

**Metric Group Name**: FEC_History  
**Default Collection**: True  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Application
This managed entity collects performance monitoring data associated with PON downstream FEC
counters.

### Relationships
An instance of this managed entity is associated with an instance of the ANI-G managed entity.

### Attributes

| Attribute Name           | Counter Width | Description |
| -----------------------: | :-----: | :-----------|
| corrected_bytes          | 32-bits | This attribute counts the number of bytes that were corrected by the FEC function. |
| corrected_code_words     | 32-bits | This attribute counts the code words that were corrected by the FEC function. |
| uncorrectable_code_words | 32-bits | This attribute counts errored code words that could not be corrected by the FEC function. |
| total_code_words         | 32-bits | This attribute counts the total received code words. |
| fec_seconds              | 16-bits | This attribute counts seconds during which there was a forward error correction anomaly. |


## GEM Port Network CTP Monitoring History Data (Class ID 341)

This managed entity collects GEM frame performance monitoring data associated with a GEM port
network CTP. Instances of this managed entity are created and deleted by the OLT.

Note 1: One might expect to find some form of impaired or discarded frame count associated with
a GEM port. However, the only impairment that might be detected at the GEM frame level would be
a corrupted GEM frame header. In this case, no part of the header could be considered reliable
including the port ID. For this reason, there is no impaired or discarded frame count in this ME.

Note 2: This managed entity replaces the GEM port performance history data managed entity and
is preferred for new implementations.

**Metric Group Name**: GEM_Port_History  
**Default Collection**: False  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Relationships

An instance of this managed entity is associated with an instance of the GEM port network CTP
managed entity.                

### Attributes

| Attribute Name            | Counter Width | Description |
| ------------------------: | :-----: | :-----------|
| transmitted_gem_frames    | 32-bits | This attribute counts GEM frames transmitted on the monitored GEM port. |
| received_gem_frames       | 32-bits | This attribute counts GEM frames received correctly on the monitored GEM port. A correctly received GEM frame is one that does not contain uncorrectable errors and has a valid HEC. |
| received_payload_bytes    | 64-bits | This attribute counts user payload bytes received on the monitored GEM port. |
| transmitted_payload_bytes | 64-bits | This attribute counts user payload bytes transmitted on the monitored GEM port. |
| encryption_key_errors     | 32-bits | This attribute is defined in ITU-T G.987 systems only. It counts GEM frames with erroneous encryption key indexes. If the GEM port is not encrypted, this attribute counts any frame with a key index not equal to 0. If the GEM port is encrypted, this attribute counts any frame whose key index specifies a key that is not known to the ONU. |

Note 3: GEM PM ignores idle GEM frames.

Note 4: GEM PM counts each non-idle GEM frame, whether it contains an entire user frame or only
a fragment of a user frame.

## XgPon TC Performance Monitoring History Data (Class ID 344)

This managed entity collects performance monitoring data associated with the XG-PON
transmission convergence layer, as defined in ITU-T G.987.3.

**Metric Group Name**: xgPON_TC_History  
**Default Collection**: False  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Relationships
An instance of this managed entity is associated with an ANI-G.

### Attributes

All counters are 32-bits wide.

| Attribute Name            | Description |
| ------------------------: | :-----------|
| psbd_hec_error_count      | This attribute counts HEC errors in any of the fields of the downstream physical sync block. |
| xgtc_hec_error_count      | This attribute counts HEC errors detected in the XGTC header. |
| unknown_profile_count     | This attribute counts the number of grants received whose specified profile was not known to the ONU. |
| transmitted_xgem_frames   | This attribute counts the number of non-idle XGEM frames transmitted. If an SDU is fragmented, each fragment is an XGEM frame and is counted as such. |
| fragment_xgem_frames      | This attribute counts the number of XGEM frames that represent fragmented SDUs, as indicated by the LF bit = 0. |
| xgem_hec_lost_words_count | This attribute counts the number of four-byte words lost because of an XGEM frame HEC error. In general, all XGTC payload following the error is lost, until the next PSBd event. |
| xgem_key_errors           | This attribute counts the number of downstream XGEM frames received with an invalid key specification. The key may be invalid for several reasons. |
| xgem_hec_error_count      | This attribute counts the number of instances of an XGEM frame HEC error. |

## XgPon Downstream Performance Monitoring History Data (Class ID 345)

This managed entity collects performance monitoring data associated with the XG-PON
transmission convergence layer, as defined in ITU-T G.987.3. It collects counters associated with
downstream PLOAM and OMCI messages.

**Metric Group Name**: xgPON_Downstream_History  
**Default Collection**: False  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

### Relationships

An instance of this managed entity is associated with an ANI-G.           

### Attributes
     
All counters are 32-bits wide.

| Attribute Name                          | Description |
| --------------------------------------: | :-----------|
| ploam_mic_error_count                   | This attribute counts MIC errors detected in downstream PLOAM messages, either directed to this ONU or broadcast to all ONUs. |
| downstream_ploam_messages_count         | This attribute counts PLOAM messages received, either directed to this ONU or broadcast to all ONUs. |
| profile_messages_received               | This attribute counts the number of profile messages received, either directed to this ONU or broadcast to all ONUs. |
| ranging_time_messages_received          | This attribute counts the number of ranging_time messages received, either directed to this ONU or broadcast to all ONUs. |
| deactivate_onu_id_messages_received     | This attribute counts the number of deactivate_ONU-ID messages received, either directed to this ONU or broadcast to all ONUs. Deactivate_ONU-ID messages do not reset this counter. |
| disable_serial_number_messages_received | This attribute counts the number of disable_serial_number messages received, whose serial number specified this ONU. |
| request_registration_messages_received  | This attribute counts the number request_registration messages received. |
| assign_alloc_id_messages_received       | This attribute counts the number of assign_alloc-ID messages received. |
| key_control_messages_received           | This attribute counts the number of key_control messages received, either directed to this ONU or broadcast to all ONUs. |
| sleep_allow_messages_received           | This attribute counts the number of sleep_allow messages received, either directed to this ONU or broadcast to all ONUs. |
| baseline_omci_messages_received_count   | This attribute counts the number of OMCI messages received in the baseline message format. |
| extended_omci_messages_received_count   | This attribute counts the number of OMCI messages received in the extended message format. |
| assign_onu_id_messages_received         | This attribute counts the number of assign_ONU-ID messages received since the last re-boot. |
| omci_mic_error_count                    | This attribute counts MIC errors detected in OMCI messages directed to this ONU. |

## XgPon Upstream Performance Monitoring History Data (Class ID 346)

This managed entity collects performance monitoring data associated with the XG-PON
transmission convergence layer, as defined in ITU-T G.987.3. It counts upstream PLOAM
messages transmitted by the ONU.

**Metric Group Name**: xgPON_Upstream_History  
**Default Collection**: False  
**Default Interval**:  15 minutes & aligned to wall-clock. Read-Only

###Relationships

An instance of this managed entity is associated with an ANI-G.          

### Attributes

All counters are 32-bits wide.

| Attribute Name                  | Description |
| ------------------------------: | :-----------|
| upstream_ploam_message_count    | This attribute counts PLOAM messages transmitted upstream, excluding acknowledge messages. |
| serial_number_onu_message_count | This attribute counts Serial_number_ONU PLOAM messages transmitted. |
| registration_message_count      | This attribute counts registration PLOAM messages transmitted. |
| key_report_message_count        | This attribute counts key_report PLOAM messages transmitted. |
| acknowledge_message_count       | This attribute counts acknowledge PLOAM messages transmitted. It includes all forms of acknowledgement, including those transmitted in response to a PLOAM grant when the ONU has nothing to send. |
| sleep_request_message_count     | This attribute counts sleep_request PLOAM messages transmitted. |

# Remaining Work Items

- The enable/disable of a PM group (CLI/NBI) should control whether or not a PM interval ME is created and collected.