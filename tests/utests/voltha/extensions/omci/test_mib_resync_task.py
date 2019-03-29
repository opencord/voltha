#
# Copyright 2017 the original author or authors.
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
from unittest import main, TestCase
from voltha.extensions.omci.omci_entities import *
from voltha.extensions.omci.tasks.mib_resync_task import MibResyncTask
from voltha.extensions.omci.database.mib_db_dict import MibDbVolatileDict as OnuDB
from voltha.extensions.omci.database.mib_db_ext import MibDbExternal as OltDB
from mock.mock_adapter_agent import MockAdapterAgent, MockDevice

_DEVICE_ID = 'br-549'


class TestOmciMibResyncTask(TestCase):
    def setUp(self):
        self.adapter_agent = MockAdapterAgent()
        self.adapter_agent.add_device(MockDevice(_DEVICE_ID))  # For Entity class lookups

        self.onu_db = OnuDB(self.adapter_agent)
        self.olt_db = OltDB(self.adapter_agent)

        self.onu_db.start()
        self.olt_db.start()

        self.olt_db.add(_DEVICE_ID)
        self.onu_db.add(_DEVICE_ID)

        self.task = MibResyncTask(self.adapter_agent, _DEVICE_ID)

    def tearDown(self):
        self.onu_db.stop()
        self.olt_db.stop()

    def test_not_same_type_dbs(self):
        #
        # OLT DB is a copy of the 'external' DB, ONU is a volatile DB
        #
        self.assertNotEqual(type(self.olt_db), type(self.onu_db))

    def test_db_same_format_str_field_serialization(self):
        class_id = OltG.class_id
        inst_id = 0
        attributes = {
            'olt_vendor_id': 'ABCD',             # StrFixedLenField(4)
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_mac_address_ip_field_serialization(self):
        class_id = IpHostConfigData.class_id
        inst_id = 0
        attributes = {
            'mac_address': '00:01:02:03:04:05',             # MACField
            'ip_address': '1.2.3.4',                        # IPField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_byte_and_short_field_serialization(self):
        class_id = UniG.class_id
        inst_id = 0
        attributes = {
            'administrative_state': int(1),                # ByteField
            'non_omci_management_identifier': int(12345)   # IPField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_int_field_serialization(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes = {
            'related_port': int(1234567)    # IntField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_long_field_serialization(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes = {
            'packet_drop_queue_thresholds': int(0x1234)        # LongField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_bit_field_serialization(self):
        class_id = OntG.class_id
        inst_id = 0
        attributes = {
            'extended_tc_layer_options': long(0x1234),        # BitField(16)
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_list_field_serialization(self):
        class_id = VlanTaggingFilterData.class_id
        inst_id = 0
        vlan_filter_list = [0] * 12
        vlan_filter_list[0] = 0x1234

        attributes = {
            'vlan_filter_list': vlan_filter_list,        # FieldListField
            'forward_operation': 0,
            'number_of_entries': 1
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_db_same_format_complex_json_serialization(self):
        class_id = ExtendedVlanTaggingOperationConfigurationData.class_id
        inst_id = 0x202
        table_data = VlanTaggingOperation(
            filter_outer_priority=15,
            filter_inner_priority=8,
            filter_inner_vid=1024,
            filter_inner_tpid_de=5,
            filter_ether_type=0,
            treatment_tags_to_remove=1,
            pad3=2,
            treatment_outer_priority=15,
            treatment_inner_priority=8,
            treatment_inner_vid=1024,
            treatment_inner_tpid_de=4
        )
        attributes = dict(
            received_frame_vlan_tagging_operation_table=table_data
        )
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_on_olt_only(self):
        class_id = GemInterworkingTp.class_id
        inst_id = 0
        attributes = {
            'gal_loopback_configuration': int(1)
        }
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 1)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)
        self.assertEqual(olt_only, [(class_id, inst_id)])

        # Now a little more complex (extra instance on the OLT
        self.olt_db.set(_DEVICE_ID, class_id, inst_id + 1, attributes)
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 1)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)
        self.assertEqual(olt_only, [(class_id, inst_id + 1)])

    def test_on_onu_only(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes = {
            'related_port': int(1234567)    # IntField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 1)
        self.assertEqual(len(attr_diffs), 0)
        self.assertEqual(onu_only, [(class_id, inst_id)])   # Test contents of what was returned

        # Now a little more complex (extra instance on the ONU
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.onu_db.set(_DEVICE_ID, class_id, inst_id + 1, attributes)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 1)
        self.assertEqual(len(attr_diffs), 0)
        self.assertEqual(onu_only, [(class_id, inst_id + 1)])   # Test contents of what was returned

    def test_on_attr_different_value(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes_olt = {
            'weight': int(12)    # ByteField
        }
        attributes_onu = {
            'weight': int(34)    # ByteField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes_onu)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes_olt)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 1)
        self.assertEqual(attr_diffs, [(class_id, inst_id, 'weight')])

    def test_ignore_read_only_attribute_differences(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes_olt = {
            'related_port': int(1234),      # IntField (R/W)
            'maximum_queue_size': int(222)  # Only on OLT but read-only
        }
        attributes_onu = {
            'related_port': int(1234)    # IntField (R/W)
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes_onu)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes_olt)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 0)

    def test_on_attr_more_on_olt(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes_olt = {
            'related_port': int(1234),       # IntField
            'back_pressure_time': int(1234)  # IntField
        }
        attributes_onu = {
            'related_port': int(1234)  # IntField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes_onu)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes_olt)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 1)
        self.assertEqual(attr_diffs, [(class_id, inst_id, 'back_pressure_time')])

    def test_on_attr_more_on_onu(self):
        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes_olt = {
            'related_port': int(1234)  # IntField
        }
        attributes_onu = {
            'related_port': int(1234),       # IntField
            'back_pressure_time': int(5678)  # IntField
        }
        self.onu_db.set(_DEVICE_ID, class_id, inst_id, attributes_onu)
        self.olt_db.set(_DEVICE_ID, class_id, inst_id, attributes_olt)

        db_copy = self.olt_db.query(_DEVICE_ID)
        db_active = self.onu_db.query(_DEVICE_ID)

        olt_only, onu_only, attr_diffs = self.task.compare_mibs(db_copy, db_active)

        self.assertEqual(len(olt_only), 0)
        self.assertEqual(len(onu_only), 0)
        self.assertEqual(len(attr_diffs), 1)
        self.assertEqual(attr_diffs, [(class_id, inst_id, 'back_pressure_time')])


if __name__ == '__main__':
    main()
