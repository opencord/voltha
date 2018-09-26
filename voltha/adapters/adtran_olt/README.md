# Adtran OLT Device Adapter
To preprovision an Adtran OLT, you will need to provide the IP Address and 
the NETCONF/REST credentials for the device.  The NETCONF/REST credentials are an
extension of the existing **preprovision_olt** command and these are placed after
entering two dashes '_--_'.  The full syntax to use is.

| Short | Long               | Default    | Notes |
| :---: | :----------------: | :--------: | ----- |
|  -u   | --nc_username      | ''         | NETCONF Username |
|  -p   | --nc_password      | ''         | NETCONF Password |
|  -t   | --nc_port          | 830        | NETCONF TCP Port |
|  -U   | --rc_username      | ''         | REST Username |
|  -P   | --rc_password      | ''         | REST Password |
|  -T   | --rc_port          | 8081       | REST TCP Port |
|  -z   | --zmq_port         | 5656       | ZeroMQ OMCI Proxy Port |
|  -M   | --multicast_vlan   | 4000       | Multicast VLANs (comma-delimited) |
|  -v   | --untagged_vlan    | 4092       | VLAN wrapper for untagged ONU frames |
|  -Z   | --pio_port         | 5657       | PIO Service ZeroMQ Port |
|  -X   | --xpon_enable      | False      | Support BBF WT-386 xPON CLI/NBI provisioning |

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

In addition to specifying the Adtran OLT by a single IP address, the host & port provisioning option
is also supported. This allows you to configure the address of the Adtran OLT with the same command line
option as the OpenOLT device adapter. For the port number, just specify the netconf port (default 830)
as in:

```bash
    preprovision_olt -t adtran_olt -H 10.17.174.193:830
```
or
```bash
    preprovision_olt -t adtran_olt --host_and_port 10.17.174.193:830
```


## xPON Provisioning Support

Currently the Adtran Device Adapter supports xPON provisioning to enable PON ports, or activate ONUs, you
must use the appropriate commands. In the VOLTHA v2.0 release (Q4 2018?), the xPON provisioning will be removed
from VOLTHA and replaced with Technology Profiles. _By default, this provisioning is now disabled and you should
use the '-X' extra-arguments provisioning command switch if you wish to use it_.

### REST Based xPON Pre-Provisioning
In addition to CLI provisioning, the Adtran OLT Device Adapter can also be provisioned though the
VOLTHA Northbound REST API. The following examples show curl commands when running with the **_Consul_**
key-value store. Similar curl commands can be used when **_etcd_** is used as the key value store

```bash
VOLTHA_IP=localhost
OLT_IP=10.17.174.228
REST_PORT=`curl -s http://localhost:8500/v1/catalog/service/voltha-envoy-8443 | jq -r '.[0].ServicePort'`
    
curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/devices \
 --header 'Content-Type: application/json' --header 'Accept: application/json' \
 -d "{\"type\": \"adtran_olt\",\"ipv4_address\": \"${OLT_IP}\",\"extra_args\": \"-u admin -p admin -U ADMIN -P ADMIN\"}" \
| jq '.' | tee /tmp/adtn-olt.json
```
This will not only pre-provision the OLT, but it will also return the created VOLTHA Device ID for use other commands.
The output is also shown on the console as well:

```bash    
curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/devices \
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
Besides specifying the "ipv4_address" leaf, you can alternatively use the "host_and_port" leaf to
provide the IP Host address and the NetCONF port as in "10.17.174.228:830"

### Enabling the Pre-Provisioned OLT
To enable the OLT, you need the retrieve the OLT Device ID and issue a POST request to the proper URL as in:
```bash
DEVICE_ID=$(jq .id /tmp/adtn-olt.json | sed 's/"//g')

curl -k -s -X POST https://${VOLTHA_IP}:${REST_PORT}/api/v1/local/devices/${DEVICE_ID}/enable
```
#### Other REST APIs
To list out any devices, you can use the following command:

```bash
curl -k -s  https://${VOLTHA_IP}:${REST_PORT}/api/v1/devices | json_pp
```

Other API endpoints (beyond the /v1/ field above) can be listed with the following command

```bash
curl -k -s https://${VOLTHA_IP}:${REST_PORT}/api/v1 | json_pp
```

# Tested OLT Device Driver versions

The minimum version number of for the OLT software is: *_11971320F1-ML-3309_* or later

