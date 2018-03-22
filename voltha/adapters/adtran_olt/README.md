# Adtran OLT Device Adapter
To preprovision an Adtran OLT, you will need to provide the IP Address and 
the NETCONF/REST credentials for the device.  The NETCONF/REST credentials are an
extension of the existing **preprovision_olt** command and these are placed after
entering two dashes '_--_'.  The full syntax to use is.

| Short | Long             | Default | Notes |
| :---: | :--------------: | :-----: | ----- |
|  -u   | --nc_username    | ''      | NETCONF Username |
|  -p   | --nc_password    | ''      | NETCONF Password |
|  -t   | --nc_port        | 830     | NETCONF TCP Port |
|  -U   | --rc_username    | ''      | REST Username |
|  -P   | --rc_password    | ''      | REST Password |
|  -T   | --rc_port        | 8081    | REST TCP Port |
|  -z   | --zmq_port       | 5656    | ZeroMQ OMCI Proxy Port |
|  -M   | --multicast_vlan | 4000    | Multicast VLANs (comma-delimeted) |
|  -V   | --packet_in_vlan | 4000    | OpenFlow Packet-In/Out VLAN, Zero to disable |
|  -v   | --untagged_vlan  | 4092    | VLAN wrapper for untagged ONU frames |

For example, if your Adtran OLT is address 10.17.174.193 with the default TCP ports and
NETCONF credentials of admin/admin and REST credentials of ADMIN/ADMIN, the command line
would be:

```bash
    preprovision_olt -t adtran_olt -i 10.17.174.193 -- -u admin -p admin -U ADMIN -P ADMIN
```
or
```bash
    preprovision_olt -t adtran_olt -i 10.17.174.193 -- --nc_username admin --nc_password admin --rc_username ADMIN --rc_password ADMIN
```

Currently the Adtran Device Adapter will enable all PON ports on startup and attempt to activate any discovered ONUs.
This behaviour will change once PON Management is fully supported.

## REST Based Pre-Provisioning
In addition to CLI provisioning, the Adtran OLT Device Adapter can also be provisioned though the
VOLTHA Northbound REST API. 

```bash
VOLTHA_IP=localhost
OLT_IP=10.17.174.228
REST_PORT=`docker inspect compose_chameleon_1 | jq -r '.[0].NetworkSettings.Ports["8881/tcp"][0].HostPort'`
    
curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/local/devices \
 --header 'Content-Type: application/json' --header 'Accept: application/json' \
 -d "{\"type\": \"adtran_olt\",\"ipv4_address\": \"${OLT_IP}\",\"extra_args\": \"-u admin -p admin -U ADMIN -P ADMIN\"}" \
| jq '.' | tee /tmp/adtn-olt.json
```
This will not only pre-provision the OLT, but it will also return the created VOLTHA Device ID for use other commands.
The output is also shown on the console as well:

```bash
REST_PORT=`docker inspect compose_chameleon_1 | jq -r '.[0].NetworkSettings.Ports["8881/tcp"][0].HostPort'`
    
curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/local/devices \
  --header 'Content-Type: application/json' --header 'Accept: application/json' \
  -d "{\"type\": \"adtran_olt\",\"ipv4_address\": \"${OLT_IP}\",\"extra_args\": \"-u admin -p admin -U ADMIN -P ADMIN\"}" \
| jq '.' | tee /tmp/adtn-olt.json
{
  "extra_args": "-u admin -p admin -U ADMIN -P ADMIN",
  "vendor": "",
  "channel_terminations": [],
  "parent_port_no": 0,
  "connect_status": "UNKNOWN",
  "root": false,
  "adapter": "adtran_olt",
  "vlan": 0,
  "hardware_version": "",
  "ports": [],
  "ipv4_address": "10.17.174.228",
  "parent_id": "",
  "oper_status": "UNKNOWN",
  "admin_state": "PREPROVISIONED",
  "reason": "",
  "serial_number": "",
  "model": "",
  "type": "adtran_olt",
  "id": "00017cbb382b9260",
  "firmware_version": ""
}
```
## Enabling the Pre-Provisioned OLT
To enable the OLT, you need the retrieve the OLT Device ID and issue a POST request to the proper URL as in:
```bash
DEVICE_ID=$(jq .id /tmp/adtn-olt.json | sed 's/"//g')

curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/local/devices/${DEVICE_ID}/enable
```
### Other REST APIs
A full list of URLs supported by VOLTHA can be obtained from the swagger API pointing
your favorite Internet Browser at: **https://${VOLTHA_IP}:${REST_PORT}/#**

To list out any devices, you can use the following command:

```bash
curl -k -s  https://${VOLTHA_IP}:${REST_PORT}/api/v1/local/devices | json_pp
```

# Tested OLT Device Driver versions

The minimum version number of for the OLT software is: *_11971320F1-ML-2287_*
The specific PON-Agent version number is: _*ngpon2_agent-4.0.37-1.545.702565*_

At this time, the version numbers above are also the latest ones tested. Work on validating
newer releases is currently underway.
