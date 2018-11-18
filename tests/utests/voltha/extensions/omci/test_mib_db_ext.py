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

from voltha.extensions.omci.database.mib_db_ext import *
from voltha.extensions.omci.database.mib_db_api import MODIFIED_KEY, CREATED_KEY,\
    DEVICE_ID_KEY, MDS_KEY, LAST_SYNC_KEY
from voltha.extensions.omci.omci_cc import UNKNOWN_CLASS_ATTRIBUTE_KEY
from mock.mock_adapter_agent import MockAdapterAgent, MockDevice
from nose.tools import raises, assert_raises
import time

_DEVICE_ID = 'br-549'


class TestOmciMibDbExt(TestCase):

    def setUp(self):
        self.adapter_agent = MockAdapterAgent()
        self.adapter_agent.add_device(MockDevice(_DEVICE_ID))  # For Entity class lookups
        self.db = MibDbExternal(self.adapter_agent)

    def tearDown(self):
        self.db.stop()

    def test_start_stop(self):
        # Simple start stop
        self.assertFalse(self.db.active)
        self.db.start()
        self.assertTrue(self.db.active)
        self.db.stop()
        self.assertFalse(self.db.active)

        # Start after start still okay
        self.db.start()
        self.db.start()
        self.assertTrue(self.db.active)

        self.db.stop()
        self.db.stop()
        self.assertFalse(self.db.active)

    @raises(DatabaseStateError)
    def test_bad_state_add(self):
        self.db.add(_DEVICE_ID)

    @raises(DatabaseStateError)
    def test_bad_state_remove(self):
        self.db.remove(_DEVICE_ID)

    @raises(DatabaseStateError)
    def test_bad_state_query_1(self):
        self.db.query(_DEVICE_ID, 0)

    @raises(DatabaseStateError)
    def test_bad_state_query_2(self):
        self.db.query(_DEVICE_ID, 0, 0)

    @raises(DatabaseStateError)
    def test_bad_state_query_3(self):
        self.db.query(_DEVICE_ID, 0, 0, 'test')

    @raises(DatabaseStateError)
    def test_bad_state_set(self):
        self.db.set(_DEVICE_ID, 0, 0, {'test': 123})

    @raises(DatabaseStateError)
    def test_bad_state_delete(self):
        self.db.delete(_DEVICE_ID, 0, 0)

    @raises(KeyError)
    def test_no_device_query(self):
        self.db.start()
        self.db.query(_DEVICE_ID)

    def test_no_device_last_sync(self):
        self.db.start()
        # Returns None, not a KeyError
        value = self.db.get_last_sync(_DEVICE_ID)
        self.assertIsNone(value)

    def test_no_device_mds(self):
        self.db.start()
        # Returns None, not a KeyError
        value = self.db.get_mib_data_sync(_DEVICE_ID)
        self.assertIsNone(value)

    @raises(KeyError)
    def test_no_device_save_last_sync(self):
        self.db.start()
        self.db.save_last_sync(_DEVICE_ID, datetime.utcnow())

    @raises(KeyError)
    def test_no_device_save_mds(self):
        self.db.start()
        self.db.save_mib_data_sync(_DEVICE_ID, 123)

    def test_param_types(self):
        self.db.start()
        assert_raises(TypeError, self.db.add, 123)
        assert_raises(TypeError, self.db.remove, 123)
        assert_raises(TypeError, self.db.query, 123)

        assert_raises(TypeError, self.db.get_mib_data_sync, 123)
        assert_raises(TypeError, self.db.save_mib_data_sync, 123, 0)
        assert_raises(TypeError, self.db.save_mib_data_sync, _DEVICE_ID, 'zero')

        assert_raises(TypeError, self.db.get_last_sync, 123)
        assert_raises(TypeError, self.db.save_last_sync, 123, datetime.utcnow())
        assert_raises(TypeError, self.db.save_last_sync, _DEVICE_ID, 'bad-date')

        assert_raises(TypeError, self.db.set, 123, 0, 0, {'test': 0})
        assert_raises(TypeError, self.db.set, None, 0, 0, {'test': 0})
        assert_raises(ValueError, self.db.set, _DEVICE_ID, None, 0, {'test': 0})
        assert_raises(ValueError, self.db.set, _DEVICE_ID, 0, None, {'test': 0})
        assert_raises(TypeError, self.db.set, _DEVICE_ID, 0, 0, None)
        assert_raises(TypeError, self.db.set, _DEVICE_ID, 0, 0, 'not-a-dict')

        assert_raises(ValueError, self.db.set, _DEVICE_ID, -1, 0, {'test': 0})
        assert_raises(ValueError, self.db.set, _DEVICE_ID, 0x10000, 0, {'test': 0})
        assert_raises(ValueError, self.db.set, _DEVICE_ID, 0, -1, {'test': 0})
        assert_raises(ValueError, self.db.set, _DEVICE_ID, 0, 0x10000, {'test': 0})

        assert_raises(TypeError, self.db.delete, 123, 0, 0)
        assert_raises(ValueError, self.db.delete, _DEVICE_ID, -1, 0)
        assert_raises(ValueError, self.db.delete, _DEVICE_ID, 0x10000, 0)
        assert_raises(ValueError, self.db.delete, _DEVICE_ID, 0, -1)
        assert_raises(ValueError, self.db.delete, _DEVICE_ID, 0, 0x10000)

    def test_add_remove_device(self):
        self.db.start()

        # Remove of non-existent device is not an error
        assert_raises(KeyError, self.db.query, _DEVICE_ID)
        self.db.remove(_DEVICE_ID)

        start_time = datetime.utcnow()
        self.db.add(_DEVICE_ID)
        dev_data = self.db.query(_DEVICE_ID)

        self.assertEqual(dev_data[DEVICE_ID_KEY], _DEVICE_ID)
        self.assertEquals(dev_data[MDS_KEY], 0)
        self.assertIsNone(dev_data[LAST_SYNC_KEY])
        self.assertEqual(dev_data[VERSION_KEY], MibDbExternal.CURRENT_VERSION)

        self.assertGreaterEqual(self.db.created, start_time)

        # Remove it
        self.db.remove(_DEVICE_ID)
        assert_raises(KeyError, self.db.query, _DEVICE_ID)

        # Remove of non-existant dev okay
        self.db.remove(_DEVICE_ID +'abcd')

        # Overwrite tests
        self.db.add(_DEVICE_ID)
        assert_raises(KeyError, self.db.add, _DEVICE_ID)
        self.db.add(_DEVICE_ID, overwrite=True)  # This is okay

    def test_mib_data_sync(self):
        self.db.start()
        self.db.add(_DEVICE_ID)
        self.assertEquals(self.db.get_mib_data_sync(_DEVICE_ID), 0)

        self.db.save_mib_data_sync(_DEVICE_ID, 100)
        self.assertEqual(self.db.get_mib_data_sync(_DEVICE_ID), 100)

        assert_raises(ValueError, self.db.save_mib_data_sync, _DEVICE_ID, -1)
        assert_raises(ValueError, self.db.save_mib_data_sync, _DEVICE_ID, 256)

    def test_last_sync(self):
        self.db.start()
        self.assertIsNone(self.db.get_last_sync(_DEVICE_ID))

        self.db.add(_DEVICE_ID)
        self.assertIsNone(self.db.get_last_sync(_DEVICE_ID))

        now = datetime.utcnow()

        self.db.save_last_sync(_DEVICE_ID, now)
        self.assertEqual(self.db.get_last_sync(_DEVICE_ID), now)

        assert_raises(TypeError, self.db.save_last_sync, _DEVICE_ID, 'hello')

    def test_set_and_query(self):
        self.db.start()
        self.db.add(_DEVICE_ID)     # Base device DB created here
        time.sleep(0.1)

        class_id = OntG.class_id
        inst_id = 0
        attributes = {'vendor_id': 'ABCD'}

        start_time = datetime.utcnow()
        set_occurred = self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.assertTrue(set_occurred)
        end_time = datetime.utcnow()

        dev_data = self.db.query(_DEVICE_ID)
        self.assertEqual(dev_data[DEVICE_ID_KEY], _DEVICE_ID)

        dev_classes = [v for k, v in dev_data.items() if isinstance(k, int)]

        self.assertEqual(len(dev_classes), 1)
        class_data = dev_classes[0]

        self.assertEqual(class_data[CLASS_ID_KEY], class_id)

        class_insts = [v for k, v in class_data.items() if isinstance(k, int)]

        self.assertEqual(len(class_insts), 1)
        inst_data = class_insts[0]

        self.assertEqual(inst_data[INSTANCE_ID_KEY], inst_id)
        self.assertGreaterEqual(inst_data[MODIFIED_KEY], start_time)
        self.assertLessEqual(inst_data[MODIFIED_KEY], end_time)
        self.assertLessEqual(inst_data[CREATED_KEY], inst_data[MODIFIED_KEY])

        inst_attributes = inst_data[ATTRIBUTES_KEY]
        self.assertEqual(len(inst_attributes), 1)

        self.assertTrue('vendor_id' in inst_attributes)
        self.assertEqual(inst_attributes['vendor_id'], attributes['vendor_id'])

        ########################################
        # Query with device and class. Should be same as from full device query
        cls_2_data = self.db.query(_DEVICE_ID, class_id)

        self.assertEqual(class_data[CLASS_ID_KEY], cls_2_data[CLASS_ID_KEY])

        cl2_insts = {k:v for k, v in cls_2_data.items() if isinstance(k, int)}
        self.assertEqual(len(cl2_insts), len(class_insts))

        # Bad class id query
        cls_no_data = self.db.query(_DEVICE_ID, class_id + 1)
        self.assertTrue(isinstance(cls_no_data, dict))
        self.assertEqual(len(cls_no_data), 0)

        ########################################
        # Query with device, class, instance
        inst_2_data = self.db.query(_DEVICE_ID, class_id, inst_id)

        self.assertEqual(inst_data[INSTANCE_ID_KEY], inst_2_data[INSTANCE_ID_KEY])
        self.assertEqual(inst_data[MODIFIED_KEY], inst_2_data[MODIFIED_KEY])
        self.assertEqual(inst_data[CREATED_KEY], inst_2_data[CREATED_KEY])

        inst2_attr = inst_2_data[ATTRIBUTES_KEY]
        self.assertEqual(len(inst2_attr), len(inst_attributes))

        # Bad instance id query
        inst_no_data = self.db.query(_DEVICE_ID, class_id, inst_id + 100)
        self.assertTrue(isinstance(inst_no_data, dict))
        self.assertEqual(len(inst_no_data), 0)

        ########################################
        # Attribute queries
        attr_2_data = self.db.query(_DEVICE_ID, class_id, inst_id, 'vendor_id')
        self.assertEqual(attr_2_data['vendor_id'], attributes['vendor_id'])

        attr_3_data = self.db.query(_DEVICE_ID, class_id, inst_id, ['vendor_id'])
        self.assertEqual(attr_3_data['vendor_id'], attributes['vendor_id'])

        attr_4_data = self.db.query(_DEVICE_ID, class_id, inst_id, {'vendor_id'})
        self.assertEqual(attr_4_data['vendor_id'], attributes['vendor_id'])

        attr_no_data = self.db.query(_DEVICE_ID, class_id, inst_id, 'no_such_thing')
        self.assertTrue(isinstance(attr_no_data, dict))
        self.assertEqual(len(attr_no_data), 0)

        # Set to same value does not change modified data.  The modified is
        # at the instance level

        class_id = OntG.class_id
        inst_id = 0
        attributes = {'vendor_id': 'ABCD'}
        set_occurred = self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.assertFalse(set_occurred)

        inst_3_data = self.db.query(_DEVICE_ID, class_id, inst_id)
        self.assertEqual(inst_data[MODIFIED_KEY], inst_3_data[MODIFIED_KEY])
        self.assertEqual(inst_data[CREATED_KEY], inst_3_data[CREATED_KEY])

        # But set to new value does
        time.sleep(0.1)
        attributes = {'vendor_id': 'WXYZ'}
        set_occurred = self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        self.assertTrue(set_occurred)

        inst_4_data = self.db.query(_DEVICE_ID, class_id, inst_id)
        self.assertLess(inst_3_data[MODIFIED_KEY], inst_4_data[MODIFIED_KEY])
        self.assertEqual(inst_3_data[CREATED_KEY], inst_4_data[CREATED_KEY])

    def test_delete_instances(self):
        self.db.start()
        self.db.add(_DEVICE_ID)
        create_time = datetime.utcnow()

        class_id = GalEthernetProfile.class_id
        inst_id_1 = 0x100
        inst_id_2 = 0x200
        attributes = {'max_gem_payload_size': 1500}

        self.db.set(_DEVICE_ID, class_id, inst_id_1, attributes)
        self.db.set(_DEVICE_ID, class_id, inst_id_2, attributes)
        time.sleep(0.1)

        dev_data = self.db.query(_DEVICE_ID)
        cls_data = self.db.query(_DEVICE_ID, class_id)
        inst_data = {k: v for k, v in cls_data.items() if isinstance(k, int)}
        self.assertEqual(len(inst_data), 2)

        self.assertLessEqual(dev_data[CREATED_KEY], create_time)
        self.assertLessEqual(self.db.created, create_time)

        # Delete one instance
        time.sleep(0.1)
        result = self.db.delete(_DEVICE_ID, class_id, inst_id_1)
        self.assertTrue(result)     # True returned if a del actually happened

        dev_data = self.db.query(_DEVICE_ID)
        cls_data = self.db.query(_DEVICE_ID, class_id)
        inst_data = {k: v for k, v in cls_data.items() if isinstance(k, int)}
        self.assertEqual(len(inst_data), 1)

        self.assertLessEqual(dev_data[CREATED_KEY], create_time)
        self.assertLessEqual(self.db.created, create_time)

        # Delete remaining instance
        time.sleep(0.1)
        result = self.db.delete(_DEVICE_ID, class_id, inst_id_2)
        self.assertTrue(result)     # True returned if a del actually happened

        dev_data = self.db.query(_DEVICE_ID)
        cls_data = {k: v for k, v in dev_data.items() if isinstance(k, int)}
        self.assertEqual(len(cls_data), 0)
        self.assertLessEqual(dev_data[CREATED_KEY], create_time)

        # Delete returns false if not instance
        self.assertFalse(self.db.delete(_DEVICE_ID, class_id, inst_id_1))
        self.assertFalse(self.db.delete(_DEVICE_ID, class_id, inst_id_2))

    def test_on_mib_reset_listener(self):
        self.db.start()
        self.db.add(_DEVICE_ID)
        time.sleep(0.1)

        class_id = OntG.class_id
        inst_id = 0
        attributes = {'vendor_id': 'ABCD'}

        set_time = datetime.utcnow()
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)

        time.sleep(0.1)
        self.db.on_mib_reset(_DEVICE_ID)

        dev_data = self.db.query(_DEVICE_ID)
        self.assertEqual(dev_data[DEVICE_ID_KEY], _DEVICE_ID)
        self.assertLessEqual(dev_data[CREATED_KEY], set_time)
        self.assertLessEqual(self.db.created, set_time)

        self.assertFalse(any(isinstance(cls, int) for cls in dev_data.iterkeys()))

    def test_str_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = OltG.class_id
        inst_id = 0
        attributes = {
            'olt_vendor_id': 'ABCD',             # StrFixedLenField(4)
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], basestring) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_mac_address_ip_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = IpHostConfigData.class_id
        inst_id = 0
        attributes = {
            'mac_address': '00:01:02:03:04:05',             # MACField
            'ip_address': '1.2.3.4',                        # IPField
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], basestring) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_byte_and_short_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = UniG.class_id
        inst_id = 0
        attributes = {
            'administrative_state': int(1),                # ByteField
            'non_omci_management_identifier': int(12345)   # IPField
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], type(attributes[k])) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_int_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes = {
            'related_port': int(1234567)    # IntField
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], type(attributes[k])) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_long_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = PriorityQueueG.class_id
        inst_id = 0
        attributes = {
            'packet_drop_queue_thresholds': int(0x1234)        # LongField
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], type(attributes[k])) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_bit_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = OntG.class_id
        inst_id = 0
        attributes = {
            'extended_tc_layer_options': long(0x1234),        # BitField(16)
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], type(attributes[k])) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_list_field_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        class_id = VlanTaggingFilterData.class_id
        inst_id = 0
        vlan_filter_list = [0] * 12
        vlan_filter_list[0] = 0x1234

        attributes = {
            'vlan_filter_list': vlan_filter_list,        # FieldListField
            'forward_operation': 0,
            'number_of_entries': 1
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)
        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(all(isinstance(data[k], type(attributes[k])) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))

    def test_complex_json_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

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
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)

        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        table_as_dict = json.loads(table_data.to_json())

        self.assertTrue(all(isinstance(data['received_frame_vlan_tagging_operation_table'][0].fields[k],
                                       type(attributes['received_frame_vlan_tagging_operation_table'].fields[k]))
                            for k in attributes['received_frame_vlan_tagging_operation_table'].fields.keys()))
        self.assertTrue(all(data['received_frame_vlan_tagging_operation_table'][0].fields[k] ==
                            attributes['received_frame_vlan_tagging_operation_table'].fields[k]
                            for k in attributes['received_frame_vlan_tagging_operation_table'].fields.keys()))
        self.assertTrue(all(data['received_frame_vlan_tagging_operation_table'][0].fields[k] == table_as_dict[k]
                            for k in table_as_dict.keys()))

    def test_unknown_me_serialization(self):
        self.db.start()
        self.db.add(_DEVICE_ID)

        blob = '00010000000c0000000000000000000000000000000000000000'
        class_id = 0xff78
        inst_id = 0x101
        attributes = {
            UNKNOWN_CLASS_ATTRIBUTE_KEY: blob
        }
        self.db.set(_DEVICE_ID, class_id, inst_id, attributes)

        data = self.db.query(_DEVICE_ID, class_id, inst_id, attributes.keys())
        self.assertTrue(isinstance(UNKNOWN_CLASS_ATTRIBUTE_KEY, basestring))
        self.assertTrue(all(isinstance(attributes[k], basestring) for k in attributes.keys()))
        self.assertTrue(all(data[k] == attributes[k] for k in attributes.keys()))


if __name__ == '__main__':
    main()
