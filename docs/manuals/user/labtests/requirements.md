# Requirements

## Test PODs

A Test POD suitable for testing Voltha and Voltha-assisted PON networks usually contains at least the following hardware components:

* One or more disaggregated OLT devices
* One or more ONU/ONT devices per OLT
* Fiber splitters and PON fiber cabling
* For virtualized deployments, a Linux server hosting Voltha and other control
  and management plane components, as well as hosting test suites. We will refer to 
  this server as the "*Voltha integration server*"
* Optional RG and STB devices
* Optionally additional server(s) hosting simulated RG functionality
* Optionally additional dataplane switches
* Optional media converters
* Optional test instruments (Spirent, etc.) for traffic testing and certification

## Supported Specific Test PODs

At this early phase, test PODs are being defined and developed by a select set
of commercial vendors who are members of the Voltha project. Once the PODs are stable enough, their details will be described here.  Until then, please contact your (preferred) vendor for test POD specifications, BOMs, and other details.
