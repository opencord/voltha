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

**TODO**: This needs to be defined by the community with assistance from the _SEBA_
developers.

Here is an JSON example of a current alarm published on the kafka bus under the 
_voltha.alarms_ topic:

```json
{
  "id": "voltha.adtran_olt.000198f9c4d2ae80.Discovery",
  "description": "adtran_olt.000198f9c4d2ae80 - ONU DISCOVERY Alarm - DISCOVERY - Raised",
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
}```

