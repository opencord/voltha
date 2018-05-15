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
from unittest import TestCase, main
from nose.tools import assert_raises
from voltha.extensions.omci.me_frame import *
from voltha.extensions.omci.omci_me import *
from voltha.extensions.omci.omci import *


def hexify(buffer):
    """Return a hexadecimal string encoding of input buffer"""
    return ''.join('%02x' % ord(c) for c in buffer)


class TestSelectMeFrameGeneration(TestCase):

    def assertGeneratedFrameEquals(self, frame, ref):
        assert isinstance(frame, Packet)
        serialized_hexified_frame = hexify(str(frame)).upper()
        ref = ref.upper()
        if serialized_hexified_frame != ref:
            self.fail('Mismatch:\nReference:\n{}\nGenerated (bad):\n{}'.format(
                ref, serialized_hexified_frame
            ))

    def test_mib_reset_message_serialization(self):
        ref = '00004F0A000200000000000000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OntDataFrame().mib_reset()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gal_ethernet_profile(self):
        ref = '0000440A011000010030000000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = GalEthernetProfileFrame(1, max_gem_payload_size=48).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_tcont_1(self):
        ref = '0000480A010680008000040000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'

        frame = TcontFrame(0x8000, alloc_id=0x400).set()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_tcont_2(self):
        ref = '0000480A010680018000040100000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'

        frame = TcontFrame(0x8001, alloc_id=0x401).set()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_8021p_mapper_service_profile(self):
        ref = '0000440A00828000ffffffffffffffff' \
              'ffffffffffffffffffff000000000000' \
              '000000000000000000000028'
        frame = Ieee8021pMapperServiceProfileFrame(0x8000).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_service_profile(self):
        ref = '0000440A002D02010001008000140002' \
              '000f0001000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            spanning_tree_ind=False,
            learning_ind=True,
            priority=0x8000,
            max_age=20 * 256,
            hello_time=2 * 256,
            forward_delay=15 * 256,
            unknown_mac_address_discard=True
        )
        frame = MacBridgeServiceProfileFrame(0x201, attributes=data).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gem_port_network_ctp(self):
        ref = '0000440A010C01000400800003010000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'

        data = dict(
            port_id=0x400,
            tcont_pointer=0x8000,
            direction=3,
            traffic_management_pointer_upstream=0x100
        )
        frame = GemPortNetworkCtpFrame(0x100, attributes=data).create()
        self.assertGeneratedFrameEquals(frame, ref)

        # Also test direction as a string parameter
        frame = GemPortNetworkCtpFrame(0x100, port_id=0x400,
                                       tcont_id=0x8000,
                                       direction='bi-directional',
                                       upstream_tm=0x100).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gem_inteworking_tp(self):
        ref = '0000440A010A80010100058000000000' \
              '01000000000000000000000000000000' \
              '000000000000000000000028'
        frame = GemInterworkingTpFrame(0x8001,
                                       gem_port_network_ctp_pointer=0x100,
                                       interworking_option=5,
                                       service_profile_pointer=0x8000,
                                       interworking_tp_pointer=0x0,
                                       gal_profile_pointer=0x1).create()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_8021p_mapper_service_profile(self):
        ref = '0000480A008280007F80800100000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        ptrs = [0x8001, 0, 0, 0, 0, 0, 0, 0]
        frame = Ieee8021pMapperServiceProfileFrame(0x8000,
                                                   interwork_tp_pointers=ptrs).set()

        self.assertGeneratedFrameEquals(frame, ref)

        ptrs = [0x8001, 0]
        frame = Ieee8021pMapperServiceProfileFrame(0x8000,
                                                   interwork_tp_pointers=ptrs).set()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_port_configuration_data(self):
        ref = '0000440A002F21010201020380000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'

        frame = MacBridgePortConfigurationDataFrame(0x2101,
                                                    bridge_id_pointer=0x201,
                                                    port_num=2,
                                                    tp_type=3,
                                                    tp_pointer=0x8000).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_vlan_tagging_filter_data(self):
        ref = '0000440A005421010400000000000000' \
              '00000000000000000000000000000000' \
              '100100000000000000000028'
        frame = VlanTaggingFilterDataFrame(0x2101,
                                           vlan_tcis=[0x400],
                                           forward_operation=0x10).create()
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_extended_vlan_tagging_operation_configuration_data(self):
        ref = '0000440A00AB02020A04010000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            association_type=10,
            associated_me_pointer=0x401
        )
        frame = \
            ExtendedVlanTaggingOperationConfigurationDataFrame(0x202,
                                                               attributes=data)\
                .create()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_operation_configuration_data(self):
        ref = '0000480A00AB02023800810081000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            input_tpid=0x8100,
            output_tpid=0x8100,
            downstream_mode=0,  # inverse of upstream
        )
        frame = \
            ExtendedVlanTaggingOperationConfigurationDataFrame(0x202,
                                                               attributes=data)\
                .set()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_1(self):
        ref = '0000480A00AB02020400f00000008200' \
              '5000402f000000082004000000000000' \
              '000000000000000000000028'
        data = dict(
            received_frame_vlan_tagging_operation_table=\
                VlanTaggingOperation(
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
        )
        frame = \
            ExtendedVlanTaggingOperationConfigurationDataFrame(0x202,
                                                               attributes=data)\
                .set()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_2(self):
        ref = '0000480A00AB02020400F00000008200' \
              'd000402f00000008200c000000000000' \
              '000000000000000000000028'
        data = dict(
            received_frame_vlan_tagging_operation_table=
                VlanTaggingOperation(
                    filter_outer_priority=15,
                    filter_inner_priority=8,
                    filter_inner_vid=1025,
                    filter_inner_tpid_de=5,
                    filter_ether_type=0,
                    treatment_tags_to_remove=1,
                    pad3=2,
                    treatment_outer_priority=15,
                    treatment_inner_priority=8,
                    treatment_inner_vid=1025,
                    treatment_inner_tpid_de=4
                )
        )

        frame = \
            ExtendedVlanTaggingOperationConfigurationDataFrame(0x202,
                                                               attributes=data)\
                .set()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_port_configuration_data2(self):
        ref = '0000440A002F02010201010b04010000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            bridge_id_pointer=0x201,
            encapsulation_methods=0,
            port_num=1,
            port_priority=0,
            port_path_cost=0,
            port_spanning_tree_in=0,
            lan_fcs_ind=0,
            tp_type=11,
            tp_pointer=0x401,
            mac_learning_depth=0
        )
        frame = MacBridgePortConfigurationDataFrame(0x201,
                                                    attributes=data).create()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_pptp_ethernet_uni_frame(self):
        ref = '0000480A000B020109000005EE000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            administrative_state=0,  # 0 - Unlock
            max_frame_size=1518      # two-octet field
        )
        frame = PptpEthernetUniFrame(0x201,
                                     attributes=data).set()

        self.assertGeneratedFrameEquals(frame, ref)

    def test_constraint_errors(self):
        self.assertTrue(True)  # TODO Also test some attribute constraint failures

    def test_mib_upload_next(self):
        # Test for VOL-649 error. SCAPY was only originally coded for a 'get'
        # action (8-bit MIB Data Sync value) but MIB Upload Next commands have
        # a 16-bit field.
        #
        # 255 and less always worked
        OntDataFrame(sequence_number=0).mib_upload_next()
        OntDataFrame(sequence_number=255).mib_upload_next()
        # But not 256+
        OntDataFrame(sequence_number=256).mib_upload_next()
        OntDataFrame(sequence_number=1000).mib_upload_next()
        OntDataFrame(sequence_number=0xFFFE).mib_upload_next()

        # Also test the optional arguments for the other actions
        OntDataFrame().get()
        OntDataFrame(mib_data_sync=4).set()
        OntDataFrame().mib_reset()
        OntDataFrame().mib_upload()
        # OntDataFrame(ignore_arc=True).get_all_alarms()        Not yet coded
        # OntDataFrame(ignore_arc=False).get_all_alarms()       Not yet coded

        # Range/type checks
        assert_raises(ValueError, OntDataFrame, mib_data_sync=-1)
        assert_raises(ValueError, OntDataFrame, mib_data_sync=256)
        assert_raises(ValueError, OntDataFrame, sequence_number=-1)
        assert_raises(ValueError, OntDataFrame, sequence_number=0x10000)
        assert_raises(TypeError, OntDataFrame, ignore_arc=123)


if __name__ == '__main__':
    main()

