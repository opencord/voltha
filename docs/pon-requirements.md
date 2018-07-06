# PON Capability Requirements v0.3

This document summarizes high level functional requirements of a PON system to make it compatible with Voltha and the CORD-based disaggregated access design.

Voltha aims to support PON systems that adhere to the separation of control plane from hardware. That means that many protocols that used to be implemented on the OLT in legacy system are now implemented in an SDN controller, sitting "above" Voltha, thus separated from the hardware. Examples of such protocols are:

* 802.1x (EAPOL) authentication
* DHCP
* IGMP

Note: In what follows we use the term ONU as a generic term to refer to the device that terminates the subscriber end of the PON fiber, even in cases where the more accurate term would be ONT.

## Reference Diagram

Voltha may be deployed on a compute environment (e.g., in the CO), in which case it communicates with the OLTs via an aggregation network. The following reference diagram illustrates this deployment model:

![image](pon-requirements/reference-inband.svg)

Alternatively, Voltha may be depolyed onto the OLT device itself. The reference points remain the same, except that the Voltha no longer uses a L2 aggregation network to communicate with the OLT device complex, as show in the diagram below:

![image](pon-requirements/reference-internal.svg)

Despite the horizontal layout, we use the following terms in their conventional meaning in PONs:

* **Downstream** refers to data flowing _from_ the upstream network or Voltha Core _toward_ the subscriber's residential gateway (RG). In the diagram this corresponds to the left to right direction.
* **Upstream** refers to data flowing _from_ the direction of the RG _toward_ the direction of Voltha Core or the upstream network. In the diagram this corresponds to the right to left direction.

We define the following reference points:

### (Pa) Voltha Adapter Interface

Uniform, abstract, vendor agnostic programmatic (Python) interface between Voltha's Core and a vendor's OLT Adapter for Voltha.

Purpose:

* Downstream:
    * Invoking management- and control-plane operations _on_ the OLT.
    * Passing management operation protocol frames on behalf of an ONU Adapter to the ONU _via_ the OLT
    * Forwarding control protocol frames to be injected by the OLT toward the RG (e.g., 802.1x, IGMP)  
* Upstream:
    * Signaling asynchronous events to Voltha Core (e.g., OLT discovered, ONU activated, alarms, and performance metric data)
    * Forwarding control-plane messages diverted from the PON network toward the SDN controller (e.g., 802.1x, IGMP)

### (Pc) Control and Management channels

This interface carries management and control protocol communication between Voltha and the PON complex. This can include protocols terminated by the OLT, by the ONU, or by the RG. Encapsulation of these protocols at Pc can be OLT vendor specific, but their payload may be specific to the vendor of the respective device. The management protocols targeting the OLT can be completely specific to the OLT vendor.

If Voltha is connected to the OLT device via an aggregation network, Pc messages need to be isolated from other data plane traffic using an isolation mechanism applicable to the aggregation network, such as using one or more dedicated VLANs.

Purpose:

* Downstream:
    * Invoke OLT management operations using possibly proprietary protocols, specific to the OLT vendor. Examples: configure OLT device attributes; disable an ONU port.
    * Invoke ONU management operations using protocols specific to the ONU (OMCI, EOAM, etc.), and tunneled by the OLT Adapter and OLT so that it may be encapsulated at Pc in ways specific to the OLT vendor.
    * Carry control plane messages to be forwarded toward the RG. If the injection of such frames into the PON is done by the OLT, the encapsulation method of these frames at Pc can be OLT vendor specific. Thus, the OLT Adapter and the OLT play a tunneling/forwarding role.
* Upstream:
    * Respond to OLT management operations
    * Carry ONU management protocol responses from the ONU to the ONU Adapter via the OLT Adapter
    * Carry control plane protocol messages isolated by the OLT and to be destined to the SDN controller. The encapsulation of such messages can be OLT vendor specific at Pc, but must encode/preseve the source (e.g., ONU port number) so that the source of the message can be identified.

### (Pd) Data plane channels

This reference point carries all unicast and multicast "payload" data flows of the subscriber, flows with which Voltha is not be concerned, including the subscriber's Internet, VoIP and multicast-based video (TV) traffic. Thus, it can include both unicast and multicast flows. It can also include control and management plane flows for protocols not involving Voltha and the SDN controller.

### (Po) OLT upstream-facing interface

This is the interface with which an OLT device is connected to the access aggregation network, i.e., to an upstream data network and to its control- and management systems. This interface thus carries the payload of both Pd and Pc. Pc and Pd flows may be carried via the same OLT physical port (in-band management and control). In the in-band case, flows of Pd vs Pc are typically isolated by VLANs. In the case of out-of band management and control Pc and Pd may be isolated via dedicated physical ports (e.g., when Pc as a whole or portions of Pc protocols access the OLT via its management port).

### (Pr) ONU residential-facing interface

This is typically a L2 (Ethernet) interface carrying control plane and data plane flows to and from the RG. This includes all subscriber "payload" flows, such as Internet, VoIP and video service traffic, but it also includes control protocol flows terminated by Voltha or the SDN controller. However this distinction is invisible at this reference point, as the RG must be able to behave in the same way irregardless of being used in a disaggregated (Voltha-based) PON network or in a conventional legacy PON network.

## Minimal Phase 1 Requirements

While Voltha is designed to cater for a growing set of requirements and tries to approach the access devices with certain degree of genericness, in the first phase of the implementation it focuses on a specific feature set and behavior. For an OLT/ONT combo to operate with Voltha, the following is expected. Note that VOLTHA does not prescribe the functional breakdown of these requirements between the OLT Adapter and the OLT device, only that the two jointly must yield the desired functionality.

## OLT and OLT Adapter Requirements

* [R-1] OLT Adapter SHOULD be able to auto-discover new OLT devices and notify Voltha CORE about these. In the integrated case (Voltha runs on the OLT device), this is a trivial task. In the compute based implementation this requires the OLTs to regularly transmit a "beacon" signal (e.g., on a specific VLAN) and the adapter to "listen" on the given VLAN and look for OLTs not yet registered with Voltha.
* [R-2] OLT Adapter MUST be able to establish a control communication channel with the OLT. This may or may not be done in a connection oriented fashion, however, the Adapter must be able to use a heart-beat mechanism to monitor the availability of the channel and detect if communication is lost to the device. Any change in status must be signaled to Voltha core via the appropriate API.
* [R-3] Upon request from Voltha Core, the Adapter MUST be able to perform the initial activation of an OLT device. This may involve any or all of the following and must result in a state where all remaining requirements listed below (R-4, R-5, ...) are satisfiable:
    * Upgrade device to desired software level
    * Reset device to a known initial configuration
    * Download and activate "golden" device configuration
    * Gather all inventory information from device
    * Start monitoring device health and setup alarm forwarding to Adapter and Voltha Core
    * Start monitoring control communication to device and signal state changes to Voltha Core
    * Start detection of connected ONUs and notify Voltha Core on arrival/departure events
* [R-4] The OLT MUST be able to "range" ONUs and detection of a new ONU MUST be signaled to Voltha Core via the appropriate API. This API call SHALL provide a minimalistic type information on the ONU, enough to allow Voltha to associate the appropriate ONU Adapter for the ONU.
* [R-5] The OLT MUST be able to detect loss of communication with an ONU and signal the loss as well as recovery events to Voltha Core via the Adapter.
* [R-6] Upon API request, the OLT Adapter must be able to perform OLT-side activation procedures associated to a given ONU. This includes establishing a default PON channel dedicated to the ONU, as well as the installation of a small set of forwarding rules which allows any and all 802.1x (EA-POL) upstream messages to be redirected toward Voltha via the help of the OLT Adapter. It is important that the Adapter can reconstruct the source ONU port before the message is passed to Voltha Core. The mode and encapsulation of such forwarded messages from the OLT to the Adapter is up to the Adapter and the OLT. Nevertheless, here are two examples how this can be accomplished:
    * The redirected frame is handled by the control and management proxy residing on the OLT and passed up as a custom message to the Adapter. The encapsulation methods may contain any and all metadata such as source port ID.
    * A dedicated VLAN is used for all redirected packets and an additional (inner) VLAN tag is used to identify the source port. The former can be used allow the adapter to receive such frames, while the latter can be used by the adapter to reconstruct the port ID before the frame is passed up to Voltha Core.
* [R-7] The Adapter and OLT MUST allow Voltha to send and receive OMCI management frames to and from an ONU. This allows Voltha to complete the ONU-side part of the ONU activation.
* [R-8] The Adapter MUST allow Voltha to send 802.1x frames back toward the ONU via the Adapter and OLT. Voltha will use logical port numbers to address the ONU/RG, and the Adapter and OLT MUST be able to map this information to whatever is needed on the Adapter to OLT link. The injection of the EA-POL frames MUST be done such that the RG receives the frame without knowing that the 802.1x authentication happened outside of the OLT device (transparent operation).
* [R-9] The Adapter and OLT MUST allow Voltha to establish unicast forwarding of subscriber traffic upstream (toward the aggregation network) and downstream (from the aggregation network toward the subscriber). In Phase 1 at least one such channel must be supported. Frames on the uplink side may be untagged, tagged with an OLT-specific pre-configured VLAN, or dual tagged with an OLT-specific VLAN and a subscriber specific VLAN ID. In the uplink direction, selection of a static CoS bit SHALL be possible.
* [R-10] The Adapter and OLT MUST support the activation of additional control plane packet redirection, including at least for the following frame types (note that in the same way as for 802.1x, the source port MUST be conveyed such that the Adapter can identify it before the frame is passed into Voltha Core) :
    * IGMP v3 messages
    * DHCP IPv4 and IPv6 messages
* [R-11] The Adapter and OLT MUST be able support the injection of arbitrary packets by Voltha into the PON network in the downstream direction toward any of the active ONUs.
* [R-12] The Adapter and OLT SHALL allow Voltha to activate additional unicast flows associated with subscriber, with unique CoS mapping and vlan tagging options.
* [R-13] The Adapter and OLT MUST allow Voltha to add/remove ONUs to specific multicast flows (video channels). Multicast is data flows are downstream only and may arrive to the OLT at specific VLAN tags. The OLT may be asked to pop such VLAN headers before forwarding them to the PON. If the OLT maps all multicast  flows to the broadcast channel of the PON, than once the generic flow is established, not further actions many be triggered by the changes to multicast flows. However, it is likely that Voltha will need to communicate to the ONUs upon these events and the OLT MUST assist in the tunneling of the needed protocol messages (e.g., OMCI) between Voltha and the ONU (see R-7).
* [R-14] The Adapter and OLT MUST support request-based isolation of given ONU (when requested by Voltha). The isolation MUST result in a state where no frames (neither data plane nor control plane) are forwarded upstream.
* [R-15] The Adapter and OLT MUST forward relevant async events (such as OLT alarms) to Voltha Core.
* [R-16] The Adapter and OLT MUST be able to propagate async OMCI messages from the ONU to Voltha Core.
* [R-17] The Adapter and OLT MUST support the removal of any multicast forwarding flow rules.
* [R-18] The Adapter and OLT MUST support the removal of any unicast flow rules.

## ONU and ONU Adapter Requirements

[TBD]

## OLT States and Expected Behavior

Voltha intefaces with the OLT via an OLT-specific Adapter reachable via the Pa interface point. Voltha handles the OLT based on a simple state machine model and expect certain behavior from the OLT based on the state of the OLT. Below we list the states and the associated behavior.

All state changes are communicated to the OLT Adapter via an appropriate API call at Pa.

The following diagram illustrates the [not yet complete] state model.

![image](pon-requirements/olt-states.svg)

## OLT Not-exist

This is an implied state when Voltha does not know about an OLT yet. At this point an OLT can be created in one of two ways:

* The OLT is pre-provisioned from the "north", initializing it with the "Pre-provisioned" state.
* The OLT is discovered by the OLT Adapter and this is signalled to Voltha Core via an async API call. Voltha will create the OLT record with the "Discovered" state.

## OLT Pre-provisioned

In this state the Adapter is expected to seek to establish communication with the OLT either based on a periodic connection attempt or waiting for a beacon signal from the OLT. If communication is established successfully, the Adapter shall signal this to Core via Pa. This allows Voltha to request activation of the OLT via the appropriate API call at Pa.

## OLT Discovered

In this state the Adapter has no further duties. Voltha will use explicit NBI acceptance or policy based decision to move the state to Activate, thus signalling the Adapter that the OLT shall be activated.

## OLT Activate

The Adapter shall activate the OLT. This can involve:

* Downloading or upgrading firmware on the OLT as needed.
* Activating default setting and configuration, including ONU detection, alarm, KPI metric collection, etc.
* Verifying baseline behavior.

Successful or failed activation shall be signalled to Core via appropriate API calls. If successful, OLT state will be moved to Active state. If failed, OLT state will be moved to Failed, with appropriate data logs for troubleshooting and alarms.

## OLT Active

This state indicates that the OLT is ready to perform the following:

* Detect newly ranged ONUs and forward the arrival events to Core via appropriate API call at Pa.
* Receive ONU activation API call(s) from Core
* Receive ONU- and subscriber specific configuration request (e.g., flow configuration and QoS configuration).
* Forward tunneled control or management messages from Core to the ONU or RG
* Forward tunneled control or management messages from the ONU or RG and pass them to Core
* Forward ONU link status change events to Core
* Forard asynchronous alarm and log messages to Core. The source of these can be the OLT or the OLT Adapter.
* Forward periodic KPI metrics (PM data) from the OLT or OLT Adapter to Core

Note that ONU-related messages do not change the OLT state, but rather affect the ONU state model as described in the next sub-section.

## OLT Failed

[TBD]

## OLT Additional States

[TBD]

* How to model upgrade?
* How to model "down for maintenance"?

## ONU States

### ONU Non-existent

### ONU Discovered

### ONU Activate

### ONU Active

### ONU Rogue/Disabled

### ONU Failed

## ONU Additional States

## Sequence Diagrams

## Cold Start Activation Sequence

The following diagram captures the sequence of steps following a cold start of all sub-systems. This is the first sequence subject of lab testing.

![image](sequences/cold-start-high-level.svg =900x)
