# Adtran OLT Device Adapter

To preprovision an Adtran OLT, you will need to provide the IP Address and 
the NETCONF/REST credentials for the device.  The NETCONF/REST credentials are an
extension of the existing **preprovision_olt** command and these are placed after
entering two dashes '_--_'.  The full syntax to use is.

| Short | Long          | Default | Notes
| :---: + :-----------: + :-----: + -----
|  -u   | --nc_username | ''      | NETCONF username
|  -p   | --nc_password | ''      | NETCONF Password
|  -t   | --nc_port     | 830     | NETCONF TCP Port
|  -U   | --rc_username | ''      | REST USERNAME
|  -P   | --rc_password | ''      | REST PASSWORD
|  -T   | --rc_port     | 8081    | REST PORT

For example, if your Adtran OLT is address 10.17.174.193 with the default TCP ports and
NETCONF credentials of admin/admin and REST credentials of ADMIN/ADMIN, the command line
would be

```bash
    preprovision_olt -t adtran_olt -i 10.17.174.193 -- -u admin -p admin -U ADMIN -P ADMIN
```
or
```bash
    preprovision_olt -t adtran_olt -i 10.17.174.193 -- --nc_username admin --nc_password admin --rc_username ADMIN --rc_password ADMIN
```

Currently the Adtran Device Adapter will enable all PON ports on startup and attempt to activate any discovered ONUs.
This behaviour will change once PON Management is fully supported.