#
# Copyright 2018 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from hashlib import md5
from unittest import TestCase, main
from nose.tools import raises
from nose.twistedtools import deferred
from copy import deepcopy
from mock.mock_adapter_agent import MockAdapterAgent, MockCore
from mock.mock_onu_handler import MockOnuHandler
from mock.mock_olt_handler import MockOltHandler
from mock.mock_onu import MockOnu
from voltha.extensions.omci.openomci_agent import OpenOMCIAgent, OpenOmciAgentDefaults
from voltha.extensions.omci.onu_configuration import OMCCVersion
from voltha.extensions.omci.omci_defs import *
from voltha.extensions.omci.omci_entities import OntG, Ont2G, Cardholder, \
    CircuitPack, SoftwareImage, AniG, UniG
from common.utils.asleep import asleep
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict
from datetime import datetime

DEFAULT_OLT_DEVICE_ID = 'default_olt_mock'
DEFAULT_ONU_DEVICE_ID = 'default_onu_mock'
DEFAULT_PON_ID = 0
DEFAULT_ONU_ID = 0
DEFAULT_ONU_SN = 'TEST00000001'

OP = EntityOperations
RC = ReasonCodes


class TestOmciConfiguration(TestCase):
    """
    Test the OMCI read-only Configuration library methods
    """
    def setUp(self):
        self.adapter_agent = MockAdapterAgent()

        custom = deepcopy(OpenOmciAgentDefaults)
        custom['mib-synchronizer']['database'] = MibDbVolatileDict

        self.omci_agent = OpenOMCIAgent(MockCore, support_classes=custom)
        self.omci_agent.start()

    def tearDown(self):
        if self.omci_agent is not None:
            self.omci_agent.stop()

        if self.adapter_agent is not None:
            self.adapter_agent.tearDown()

    def setup_mock_olt(self, device_id=DEFAULT_OLT_DEVICE_ID):
        handler = MockOltHandler(self.adapter_agent, device_id)
        self.adapter_agent.add_device(handler.device)
        return handler

    def setup_mock_onu(self, parent_id=DEFAULT_OLT_DEVICE_ID,
                       device_id=DEFAULT_ONU_DEVICE_ID,
                       pon_id=DEFAULT_PON_ID,
                       onu_id=DEFAULT_ONU_ID,
                       serial_no=DEFAULT_ONU_SN):
        handler = MockOnuHandler(self.adapter_agent, parent_id, device_id, pon_id, onu_id)
        handler.serial_number = serial_no
        onu = MockOnu(serial_no, self.adapter_agent, handler.device_id) \
            if serial_no is not None else None
        handler.onu_mock = onu
        return handler

    def setup_one_of_each(self):
        # Most tests will use at lease one or more OLT and ONU
        self.olt_handler = self.setup_mock_olt()
        self.onu_handler = self.setup_mock_onu(parent_id=self.olt_handler.device_id)
        self.onu_device = self.onu_handler.onu_mock

        self.adapter_agent.add_child_device(self.olt_handler.device,
                                            self.onu_handler.device)
        # Add device to OpenOMCI
        self.onu_device = self.omci_agent.add_device(DEFAULT_ONU_DEVICE_ID,
                                                     self.adapter_agent)

        # Allow timeout trigger support while in disabled state for mib sync
        # to make tests run cleanly while profiling.
        self.onu_device.mib_synchronizer.machine.add_transition('timeout', 'disabled', 'disabled')

    def not_called(self, _reason):
        assert False, 'Should never be called'

    def _stuff_database(self, entries):
        """
        Stuff the MIB database with some entries that we will use during tests
        """
        database = self.onu_device.mib_synchronizer._database

        # Stuff a value into last in sync. This makes it look like
        # the ONU has been in in-sync at least once.
        self.onu_device.mib_synchronizer.last_mib_db_sync = datetime.utcnow()

        # Entry is a tuple of (class_id, instance_id, {attributes})
        for entry in entries:
            database.set(DEFAULT_ONU_DEVICE_ID, entry[0], entry[1], entry[2])

    def test_OMCCVersion(self):
        for key, value in OMCCVersion.__members__.items():
            self.assertEqual(OMCCVersion.to_enum(OMCCVersion[key].value), value)

        self.assertEqual(OMCCVersion.to_enum(-1), OMCCVersion.Unknown)

    @deferred(timeout=50000)
    def test_defaults(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        @raises(AssertionError)
        def do_my_tests(_results):
            config = self.onu_device.configuration
            # Should raise assertion if never been synchronized
            config.version

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs. This is a waiting
        # Async task from when the OpenOMCIAgent was started. But also start the
        # device so that it's queued async state machines can run as well
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_but_empty(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        def stuff_db(_results):
            self._stuff_database([])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            # On no Class ID for requested property, None should be
            # returned
            self.assertIsNone(config.version)
            self.assertIsNone(config.traffic_management_option)
            self.assertIsNone(config.onu_survival_time)
            self.assertIsNone(config.equipment_id)
            self.assertIsNone(config.omcc_version)
            self.assertIsNone(config.vendor_product_code)
            self.assertIsNone(config.total_priority_queues)
            self.assertIsNone(config.total_traffic_schedulers)
            self.assertIsNone(config.total_gem_ports)
            self.assertIsNone(config.uptime)
            self.assertIsNone(config.connectivity_capability)
            self.assertIsNone(config.qos_configuration_flexibility)
            self.assertIsNone(config.priority_queue_scale_factor)
            self.assertIsNone(config.cardholder_entities)
            self.assertIsNone(config.circuitpack_entities)
            self.assertIsNone(config.software_images)
            self.assertIsNone(config.ani_g_entities)
            self.assertIsNone(config.uni_g_entities)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_ont_g_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        version = 'abcDEF'
        tm_opt = 2
        onu_survival = 123

        def stuff_db(_results):
            self._stuff_database([
                (OntG.class_id, 0, {'version': version,
                                    'traffic_management_options': tm_opt,
                                    'ont_survival_time': onu_survival
                                    })])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            # On no Class ID for requested property, None should be
            # returned
            self.assertEqual(config.version, version)
            self.assertEqual(config.traffic_management_option, tm_opt)
            self.assertEqual(config.onu_survival_time, onu_survival)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_ont_2g_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        equip_id = 'br-549'
        omcc_ver = OMCCVersion.G_988_2012
        vend_code = 0x1234
        queues = 64
        scheds = 8
        gem_ports = 24
        uptime = 12345
        conn_capp = 0x00aa
        qos_flex = 0x001b
        queue_scale = 1

        def stuff_db(_results):
            self._stuff_database([
                (Ont2G.class_id, 0, {'equipment_id': equip_id,
                                     'omcc_version': omcc_ver.value,
                                     'vendor_product_code': vend_code,
                                     'total_priority_queue_number': queues,
                                     'total_traffic_scheduler_number': scheds,
                                     'total_gem_port_id_number': gem_ports,
                                     'sys_uptime': uptime,
                                     'connectivity_capability': conn_capp,
                                     'qos_configuration_flexibility': qos_flex,
                                     'priority_queue_scale_factor': queue_scale
                                     })])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            self.assertEqual(config.equipment_id, equip_id)
            self.assertEqual(config.omcc_version, omcc_ver)
            self.assertEqual(config.vendor_product_code, vend_code)
            self.assertEqual(config.total_priority_queues, queues)
            self.assertEqual(config.total_traffic_schedulers, scheds)
            self.assertEqual(config.total_gem_ports, gem_ports)
            self.assertEqual(config.uptime, uptime)
            self.assertEqual(config.connectivity_capability, conn_capp)
            self.assertEqual(config.qos_configuration_flexibility, qos_flex)
            self.assertEqual(config.priority_queue_scale_factor, queue_scale)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_cardholder_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        ch_entity = 0x102
        unit_type = 255
        clie_code = 'abc123'
        prot_ptr = 0

        def stuff_db(_results):
            self._stuff_database([
            (Cardholder.class_id, ch_entity, {'actual_plugin_unit_type': unit_type,
                                              'actual_equipment_id': clie_code,
                                              'protection_profile_pointer': prot_ptr,
                                              })])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            cardholder = config.cardholder_entities
            self.assertTrue(isinstance(cardholder, dict))
            self.assertEqual(len(cardholder), 1)
            self.assertEqual(cardholder[ch_entity]['entity-id'], ch_entity)
            self.assertEqual(cardholder[ch_entity]['is-single-piece'], ch_entity >= 256)
            self.assertEqual(cardholder[ch_entity]['slot-number'], ch_entity & 0xFF)
            self.assertEqual(cardholder[ch_entity]['actual-plug-in-type'], unit_type)
            self.assertEqual(cardholder[ch_entity]['actual-equipment-id'], clie_code)
            self.assertEqual(cardholder[ch_entity]['protection-profile-ptr'], prot_ptr)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_circuitpack_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        cp_entity = 0x100
        num_ports = 1
        serial_num = 'ABCD01234'
        cp_version = '1234ABCD'
        vendor_id = 'AB-9876'
        tconts = 2
        pqueues = 64
        sched_count = 8

        def stuff_db(_results):
            self._stuff_database([
                (CircuitPack.class_id, cp_entity, {'number_of_ports': num_ports,
                                                   'serial_number': serial_num,
                                                   'version': cp_version,
                                                   'vendor_id': vendor_id,
                                                   'total_tcont_buffer_number': tconts,
                                                   'total_priority_queue_number': pqueues,
                                                   'total_traffic_scheduler_number': sched_count,
                                                   })])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            circuitpack = config.circuitpack_entities
            self.assertTrue(isinstance(circuitpack, dict))
            self.assertEqual(len(circuitpack), 1)
            self.assertEqual(circuitpack[cp_entity]['entity-id'], cp_entity)
            self.assertEqual(circuitpack[cp_entity]['number-of-ports'], num_ports)
            self.assertEqual(circuitpack[cp_entity]['serial-number'], serial_num)
            self.assertEqual(circuitpack[cp_entity]['version'], cp_version)
            self.assertEqual(circuitpack[cp_entity]['vendor-id'], vendor_id)
            self.assertEqual(circuitpack[cp_entity]['total-tcont-count'], tconts)
            self.assertEqual(circuitpack[cp_entity]['total-priority-queue-count'], pqueues)
            self.assertEqual(circuitpack[cp_entity]['total-traffic-sched-count'], sched_count)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_software_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        sw_entity = 0x200
        sw_version = 'Beta-0.0.2'
        sw_hash = md5("just_a_test").hexdigest()
        prod_code = 'MySoftware'
        sw_active = True
        sw_committed = True
        sw_valid = True

        def stuff_db(_results):
            self._stuff_database([
                (SoftwareImage.class_id, sw_entity, {'version': sw_version,
                                                     'is_committed': sw_committed,
                                                     'is_active': sw_active,
                                                     'is_valid': sw_valid,
                                                     'product_code': prod_code,
                                                     'image_hash': sw_hash,
                                                     })])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            images = config.software_images
            self.assertTrue(isinstance(images, list))
            self.assertEqual(len(images), 1)
            self.assertEqual(images[0].name, 'running-revision' if sw_active else 'candidate-revision')
            self.assertEqual(images[0].version, sw_version)
            self.assertEqual(images[0].is_active, 1 if sw_active else 0)
            self.assertEqual(images[0].is_committed, 1 if sw_committed else 0)
            self.assertEqual(images[0].is_valid,  1 if sw_valid else 0)
            self.assertEqual(images[0].hash, sw_hash)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_ani_g_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        entity_id = 0x0106
        tconts = 4
        dba_report = 4

        def stuff_db(_results):
            self._stuff_database([
                (AniG.class_id, entity_id, {'total_tcont_number': tconts,
                                            'piggyback_dba_reporting': dba_report
                                            })
            ])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            anig = config.ani_g_entities
            self.assertTrue(isinstance(anig, dict))
            self.assertEqual(len(anig), 1)

            self.assertEqual(anig[entity_id]['entity-id'], entity_id)
            self.assertEqual(anig[entity_id]['slot-number'], (entity_id >> 8) & 0xff)
            self.assertEqual(anig[entity_id]['port-number'], entity_id & 0xff)
            self.assertEqual(anig[entity_id]['total-tcont-count'], tconts)
            self.assertEqual(anig[entity_id]['piggyback-dba-reporting'], dba_report)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d

    @deferred(timeout=5)
    def test_in_sync_with_uni_g_values(self):
        self.setup_one_of_each()
        self.assertEqual(len(self.omci_agent.device_ids()), 1)

        entity_id = 0x4321
        mgmt_cap = 0

        def stuff_db(_results):
            self._stuff_database([
                (UniG.class_id, entity_id, {'management_capability': mgmt_cap})
            ])

        def do_my_tests(_results):
            config = self.onu_device.configuration

            unig = config.uni_g_entities
            self.assertTrue(isinstance(unig, dict))
            self.assertEqual(len(unig), 1)

            self.assertEqual(unig[entity_id]['entity-id'], entity_id)
            self.assertEqual(unig[entity_id]['management-capability'], mgmt_cap)

        # No capabilities available until started
        self.assertIsNone(self.onu_device.configuration)

        # Yield context so that MIB Database callLater runs.
        self.onu_device.start()
        d = asleep(0.2)
        d.addCallbacks(stuff_db, self.not_called)
        d.addCallbacks(do_my_tests, self.not_called)
        return d


if __name__ == '__main__':
    main()

