#!/usr/local/bin/python

from __future__ import print_function
from sys import argv, exit, stdout
from time import sleep
import requests

def provision_olt():
    r = requests.post(url_base + "/devices", json = {"type":"asfvolt16_olt", "host_and_port":argv[1]})


    if r.status_code != 200:
        print("Failed to add device: %s" % r.text)

    device_id = r.json()['id']
    if device_id == '':
        print("Device ID is empty")
        exit(1)

    r = requests.post(url_base + "/devices/" + device_id + "/enable")

    if r.status_code != 200:
        print("Failed to enable device %s: %s" % (device_id, r.text))

    r = requests.get(url_base + "/devices/" + device_id)


    print("Waiting for device to activate", end='')
    while r.json()['oper_status'] == "ACTIVATING":
        print('.', end='')
        stdout.flush()
        sleep(5)
        r = requests.get(url_base + "/devices/" + device_id)
        
    print('')


    if r.json()['oper_status'] != "ACTIVE":
        print("Failed to enable device: %s" % r.json()['oper_status'])
        exit(1)
        
    return device_id

def xpon_olt(url_base, device_id):
    post(url_base + "/channel_groups/Manhattan", {
        "interface" : {
            "enabled" : "true",
            "name" : "Manhattan",
            "type" : "channelgroup",
            "description" : "Channel Group for Manhattan"
        },
        "data" : {
            "polling_period" : 100,
            "system_id" : "000000",
            "raman_mitigation" : "RAMAN_NONE"
        },
        "name" : "Manhattan"
    })


    post(url_base + "/channel_partitions/WTC", {
        "interface": {
            "name" : "WTC",
            "description": "Channel Partition for World Trade Center in Manhattan",
            "type": "channelpartition",
            "enabled": "true"
        },
        "data": {
            "channelgroup_ref": "Manhattan",
            "fec_downstream": "false",
            "closest_ont_distance": 0,
            "differential_fiber_distance": 20,
            "authentication_method": "SERIAL_NUMBER",
            "multicast_aes_indicator": "false"
        },
        "name": "WTC"
    })

    post(url_base + "/channel_pairs/PON%20port", {
      "interface": {
        "name" : "PON port",
        "description": "Channel Pair for Freedom Tower in WTC",
        "type": "channelpair",
        "enabled": "true",
      },
      "data": {
        "channelgroup_ref": "Manhattan",
        "channelpartition_ref": "WTC",
        "channelpair_type": "channelpair",
        "channelpair_linerate": "down_10_up_10",
        "gpon_ponid_interval": 0,
        "gpon_ponid_odn_class": "CLASS_A"
      },
      "name": "PON port"
    })

    post(url_base + "/traffic_descriptor_profiles/TDP%201", {\
     "name": "TDP 1",
     "fixed_bandwidth": "100000",
     "assured_bandwidth": "500000",
     "maximum_bandwidth": "1000000",
     "priority": 1,
     "weight": 1,
     "additional_bw_eligibility_indicator": "ADDITIONAL_BW_ELIGIBILITY_INDICATOR_NONE"
   })


    post(url_base + "/devices/" + device_id + "/channel_terminations/PON%20port", {
      "interface": {
        "name": "PON port",
        "description": "Channel Termination for Freedom Tower",
        "type": "channel-termination",
        "enabled": "true",
        "link_up_down_trap_enable": "TRAP_DISABLED"
      },
      "data": {
        "channelpair_ref": "PON port",
        "meant_for_type_b_primary_role": "false",
        "ngpon2_twdm_admin_label": 0,
        "ngpon2_ptp_admin_label": 0,
        "xgs_ponid": 0,
        "xgpon_ponid": 0,
        "gpon_ponid": "",
        "pon_tag": "",
        "ber_calc_period": 0,
        "location": "AT&T WTC OLT",
        "url_to_reach": ""
      },
      "name": "PON port"
    })
    
    # Wait for the PON to come up
    sleep(5)
    
def xpon_ont(url_base, serial_number):
    post(url_base + "/v_ont_anis/ATT%20Golden%20User", {
        "interface": {
        "name": "ATT Golden User",
        "description": "ATT Golden User in Freedom Tower",
        "type": "v-ontani",
        "enabled": "true"#,
        #"link_up_down_trap_enable": "TRAP_DISABLED"
      },
      "data": {
        "parent_ref": "WTC",
        "expected_serial_number": serial_number,
        #"expected_registration_id": "",
        "preferred_chanpair": "PON port",
        #"protection_chanpair": "",
        #"upstream_channel_speed": 0,
        "onu_id": 1
      },
      "name": "ATT Golden User"
    })

    # Wait for the ONT to come up
    sleep(5)

    post(url_base + "/ont_anis/ATT%20Golden%20User", {
        "interface": {
        "name": "ATT Golden User",
        "description": "ATT Golden User in Freedom Tower",
        "type": "ontani",
        "enabled": "true"#,
        #"link_up_down_trap_enable": "TRAP_DISABLED"
      },
      "data": {
        "upstream_fec_indicator": "true",
        "mgnt_gemport_aes_indicator": "false"
      },
      "name": "ATT Golden User"
    })

    post(url_base + "/tconts/TCont%201", {
      "name": "TCont 1",
      "interface_reference": "ATT Golden User",
      "traffic_descriptor_profile_ref": "TDP 1"#,
      #"alloc_id": 1024
    })
    
    # Wait for scheduler configuration to finish
    sleep(5)

    post(url_base + "/v_enets/Enet%20UNI%201", {
      "interface": {
        "name": "Enet UNI 1",
        "description": "Ethernet port - 1",
        "type": "v-enet",
        "enabled": "true"#,
        #"link_up_down_trap_enable": "TRAP_DISABLED"
      },
      "data": {
        "v_ontani_ref": "ATT Golden User"
      },
      "name": "Enet UNI 1"
    })

    post(url_base + "/gemports/Gemport%201", {
      "name": "Gemport 1",
      "itf_ref": "Enet UNI 1",
      "traffic_class": 2,
      "aes_indicator": "true",
      "tcont_ref": "TCont 1"#,
      #"gemport_id": 1024
    })
    
def post(url, data):
    print("POSTing to %s" % url)
    
    r = requests.post(url, json=data)
    
    print("\tstatus=%s" % r.status_code)
    
    if r.status_code != 200:
        print("POST failed: %s" % r.text)
        
    sleep(5)

if __name__ == '__main__':
    if len(argv) < 3:
        print("usage: xpon <olt_ip:port> <onu_serial_no>")
        exit(1)

    host_and_port = argv[1]
    serial_number = argv[2]

    # TODO unhardcode host
    url_base = "http://localhost:8882/api/v1"


    r = requests.get(url_base + "/devices")
    device_id = ''
    for item in r.json()['items']:
        print(item)
        if 'host_and_port' in item and item['host_and_port'] == host_and_port:
            device_id = item['id']

    if device_id == '':
        print("Device not found, provisioning")
        device_id = provision_olt()

    # Wait before starting XPON config
    sleep(2)

    xpon_olt(url_base, device_id)
    
    xpon_ont(url_base, serial_number)

