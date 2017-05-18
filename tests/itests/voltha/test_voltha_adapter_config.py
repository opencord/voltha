from unittest import main
from time import time, sleep
from tests.itests.docutests.test_utils import \
    run_long_running_command_with_timeout
from tests.itests.voltha.rest_base import RestBase
from google.protobuf.json_format import MessageToDict
from voltha.protos.device_pb2 import Device
from voltha.protos.adapter_pb2 import Adapter, AdapterConfig, \
      OnuServiceProvisioningConfigPerDevice, ExplicitOnuCfg
import simplejson, jsonschema
import re

# ~~~~~~~ Common variables ~~~~~~~

ADAPTER_CONFIG_SCHEMA = {
    "properties": {
        "config": {
            "properties": {
                "disable_auto_registration": {
                    "type": "boolean"
                },
                "log_level": {
                    "type": "string"
                },
                "onu_prov_cfgs": {
                    "items": {
                        "properties": {
                            "default_onu_cfgs": {
                                "items": {},
                                "type": "array"
                            },
                            "explicit_onu_cfgs": {
                                "items": {
                                    "properties": {
                                        "onu_id": {
                                            "type": "integer"
                                        },
                                        "serial_number": {
                                            "type": "string"
                                        }
                                    },
                                    "type": "object"
                                },
                                "type": "array"
                            },
                            "nas_id": {
                                "type": "string"
                            }
                        },
                        "type": "object"
                    },
                    "type": "array"
                }
            },
            "type": "object"
        },
        "id": {
            "type": "string"
        },
        "logical_device_ids": {
            "items": {},
            "type": "array"
        },
        "vendor": {
            "type": "string"
        },
        "version": {
            "type": "string"
        }
    },
    "type": "object"
}

ONU_IDS = [20, 21]
SERIAL_NUMS = ["987654", "987655"]
OPERATOR_ASSIGNED_DEV_ID = "124"


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class VolthaAdapterConfigTests(RestBase):
    # Retrieve details on the REST entry point
    rest_endpoint = "127.0.0.1:8881"

    # Construct the base_url
    base_url = 'http://' + rest_endpoint

    def wait_till(self, msg, predicate, interval=0.1, timeout=5.0):
        deadline = time() + timeout
        while time() < deadline:
            if predicate():
                return
            sleep(interval)
        self.fail('Timed out while waiting for condition: {}'.format(msg))

    # ~~~~~~~~~~~~ Tests ~~~~~~~~~~~~
    def test_01_voltha_adapter_explicit_config(self):
        # Make sure the Voltha REST interface is available
        self.verify_rest()

        # Pass explicit adapter config for simulated OLT
        # consists of serial number to onu_id mapping
        self.add_adapter_config()

        # Get the adapter config
        adapter_config = self.get_adapter_config()

        # validate adapter config
        self.validate_adapter_config_schema(adapter_config)

        # Create a new device
        device = self.add_device()

        # Activate the new device
        self.activate_device(device['id'])

        # wait till device moves to ACTIVE state
        self.wait_till(
            'admin state moves from ACTIVATING to ACTIVE',
            lambda: self.get('/api/v1/devices/{}'.format(device['id']))['oper_status'] in ('ACTIVE'),
            timeout=5.0)

        # issue command to detect the ONUs
        self.detect_onus(device['id'])

        # Give some time before ONUs are detected
        sleep(2.0)

        # get the list of devices
        devices = self.get_devices()

        # validate the number of ONUs and ONU_ID assignment
        self.validate_onu_devices(device['id'], devices)

    def test_02_voltha_adapter_default_config(self):
        # Make sure the Voltha REST interface is available
        self.verify_rest()

        # Get the adapter config
        adapter_config = self.get_adapter_config()

        # validate adapter config
        self.validate_adapter_config_schema(adapter_config)

        # Create a new device
        device = self.add_device()

        # Activate the new device
        self.activate_device(device['id'])

        # wait till device moves to ACTIVE state
        self.wait_till(
            'admin state moves from ACTIVATING to ACTIVE',
            lambda: self.get('/api/v1/devices/{}'.format(device['id']))['oper_status'] in ('ACTIVE'),
            timeout=5.0)

        # issue command to detect the ONUs
        self.detect_onus(device['id'])

        # Give some time before ONUs are detected
        sleep(2.0)

        # get the list of devices
        devices = self.get_devices()

        # validate the number of ONUs and ONU_ID assignment
        self.validate_onu_devices(device['id'], devices)



    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def verify_rest(self):
        self.get('/api/v1')

    def add_adapter_config(self):
        explicit_onu_cfg1=ExplicitOnuCfg(
                serial_number=SERIAL_NUMS[0],
                onu_id=ONU_IDS[0]
        )
        explicit_onu_cfg2=ExplicitOnuCfg(
                serial_number=SERIAL_NUMS[1],
                onu_id=ONU_IDS[1]
        )
        onu_service_prov_cfg=OnuServiceProvisioningConfigPerDevice(
                olt_id=OPERATOR_ASSIGNED_DEV_ID,
                explicit_onu_cfgs=[explicit_onu_cfg1, 
                                   explicit_onu_cfg2]
        )
        adapter_config=AdapterConfig(
                disable_auto_registration=False,
                onu_prov_cfgs=[onu_service_prov_cfg]
        )
        config = Adapter(
                id="simulated_olt",
                config=adapter_config
        )
        resp = self.put('/api/v1/local/adapters/simulated_olt', MessageToDict(config),
                           expected_code=200)

    def get_adapter_config(self):
        adapter_config = self.get('/api/v1/local/adapters/simulated_olt')
        return adapter_config


    # Create a new simulated device
    def add_device(self):
        device = Device(
            type='simulated_olt',
        )
        device = self.post('/api/v1/local/devices', MessageToDict(device),
                           expected_code=200)
        return device

    def get_devices(self):
        devices = self.get('/api/v1/local/devices', expected_code=200)
        return devices

    # Active the simulated device.
    def activate_device(self, device_id):
        path = '/api/v1/local/devices/{}'.format(device_id)
        self.post(path + '/enable', expected_code=200)
        device = self.get(path)
        self.assertEqual(device['admin_state'], 'ENABLED')

    def detect_onus(self, device_id):
        path = '/devices/{}/detect_onus'.format(device_id)
        self.get_sim_rest(path, expected_code=200)

    def validate_adapter_config_schema(self, adapter_config):
        try:
            jsonschema.validate(adapter_config, ADAPTER_CONFIG_SCHEMA)
        except Exception as e:
            self.assertTrue(
                False, 'Validation failed for adapter_config : {}'.format(e.message))

    def validate_onu_devices(self, device_id, devices):
        explicit_cfg_onu_cnt = 0
        default_cfg_onu_cnt = 0
        explicit_config_exists = False
        for item in devices["items"]:
            if item["vendor"] == "simulated" and \
               item["operator_assgnd_dev_id"] == OPERATOR_ASSIGNED_DEV_ID and \
               item["id"] == device_id:
                   explicit_config_exists = True
            if item["vendor"] == "simulated onu adapter" and \
               item["parent_id"] == device_id:
                proxy_address = item["proxy_address"]
                if proxy_address["onu_id"] in ONU_IDS:
                    explicit_cfg_onu_cnt += 1
                else:
                    default_cfg_onu_cnt += 1
  
        # verify the number of ONUs with explicit config is correct
        if (explicit_config_exists):
            self.assertEqual(explicit_cfg_onu_cnt, len(ONU_IDS))

        # verify the numbers of ONUs that have come up with default config
        self.assertEqual(default_cfg_onu_cnt, 2)


if __name__ == '__main__':
    main()
