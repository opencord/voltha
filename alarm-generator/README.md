## Automatic Alarm Generator

Alarm-generator is a process that sends a streat of simulate_alarm requrests to VOLTHA. It will automatically pick
between a variety of ONU-related alarms. The number of alarms per second is configurable (for example, 0.01 = one
alarm per hundred seconds), and the duration of the alarm from RAISE to CLEAR is also configurable.

See main.py for syntax and examples.
