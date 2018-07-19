# VOLTHA Alarm Library

This directory provides a common library for the creation of Alarms by adapters within VOLTHA
and should be used to insure that published alarms from different adapters use the same format

## Alarm Manager Creation

Each device handler should create an instance of the **AdapterAlarms** alarm manager shortly after
initial activation. This alarm manager is responsible for the formatting and sending of alarms
by the adapters.

## Raising and Clearing Alarms

To create a specific alarm, create an instance of the specific alarm you wish to publish
(such as **OnuDiscoveryAlarms** for newly discovered ONUs) and pass in alarm specific information
to the initialize.

Once constructed, you can call the alarm's **_raise_alarm()_** method to format and send an active
alarm, or the **_clear_alarm()_** to clear it.

# Basic Alarm Format

Here is an JSON example of a current alarm published on the kafka bus under the 
_voltha.alarms_ topic:

```json
{
  "id": "voltha.adtran_olt.000198f9c4d2ae80.Discovery",
  "description": "adtran_olt.000198f9c4d2ae80 - ONU DISCOVERY Alarm - DISCOVERY - Raised",
  "logical_device_id": "0001112233445566",
  "state": "RAISED",
  "category": "PON",
  "severity": "CRITICAL",
  "resource_id": "0",
  "type": "EQUIPMENT",
  "reported_ts": 1532031872.0,
  "raised_ts": 1532031872.0,
  "changed_ts": 0.0,
  "context": {
    "serial-number": "ADTN17230031",
    "pon-id": "0"
  }
}
```

# Remaining Work Items
This initial code is only a prelimenary sample. The following tasks need to be
added to the VOLTHA JIRA or performed in the SEBA group.

- Get a list from SEBA/VOLTHA on required alarms 

- Provide example JSON output and verify that it meets SEBA's requirements

- Get feedback from other OLT/ONU developers on any needed changes

- For the logical_device_id, this is reported in the format that the device adapter has which
  includes the vcore number (often 0001) in the first four nibble.  Should this be normalized to
  all zeros?

- Support alarm_suppression capability (via IAdapter call). Needs investigation

- TODO: Probably a few more.  Look through code for more 'TODO' Notes
