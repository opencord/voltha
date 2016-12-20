from unittest import TestCase, main

from voltha.extensions.omci.omci import *


def hexify(buffer):
    """Return a hexadecimal string encoding of input buffer"""
    return ''.join('%02x' % ord(c) for c in buffer)


def chunk(indexable, chunk_size):
    for i in range(0, len(indexable), chunk_size):
        yield indexable[i : i + chunk_size]


def hex2raw(hex_string):
    return ''.join(chr(int(byte, 16)) for byte in chunk(hex_string, 2))


class TestOmciFundamentals(TestCase):

    def test_bitpos_from_mask(self):

        f = lambda x: bitpos_from_mask(x)
        self.assertEqual(f(0), [])
        self.assertEqual(f(1), [0])
        self.assertEqual(f(3), [0, 1])
        self.assertEqual(f(255), [0, 1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(f(0x800), [11])
        self.assertEqual(f(0x811), [0, 4, 11])

        f = lambda x: bitpos_from_mask(x, 16, -1)
        self.assertEqual(f(0), [])
        self.assertEqual(f(1), [16])
        self.assertEqual(f(0x800), [5])
        self.assertEqual(f(0x801), [5, 16])


    def test_attribute_indeices_from_mask(self):

        f = EntityClass.attribute_indices_from_mask
        self.assertEqual(f(0), [])
        self.assertEqual(f(0x800), [5])
        self.assertEqual(f(0xf000), [1, 2, 3, 4])
        self.assertEqual(f(0xf804), [1, 2, 3, 4, 5, 14])

    def test_entity_attribute_serialization(self):

        e = CircuitPack(vendor_id='F')
        self.assertEqual(e.serialize(), 'F\x00\x00\x00')

        e = CircuitPack(vendor_id='FOOX')
        self.assertEqual(e.serialize(), 'FOOX')

        e = CircuitPack(vendor_id='FOOX', number_of_ports=16)
        self.assertEqual(e.serialize(), '\x10FOOX')

    def test_entity_attribute_serialization_mask_based(self):

        e = CircuitPack(
            number_of_ports=4,
            serial_number='123-123A',
            version='a1c12fba91de',
            vendor_id='BCM',
            total_tcont_buffer_number=128
        )

        # Full object
        self.assertEqual(e.serialize(),
                         '\x04123-123Aa1c12fba91de\x00\x00BCM\x00\x80')

        # Explicit mask with valid values
        self.assertEqual(e.serialize(0x800), 'BCM\x00')
        self.assertEqual(e.serialize(0x6800), '\x04123-123ABCM\x00')

        # Referring to an unfilled field is regarded as error
        self.assertRaises(OmciUninitializedFieldError, e.serialize, 0xc00)

    def test_omci_mask_value_gen(self):
        cls = CircuitPack
        self.assertEqual(cls.mask_for('vendor_id'), 0x800)
        self.assertEqual(
            cls.mask_for('vendor_id', 'bridged_or_ip_ind'), 0x900)

    reference_get_request_hex = (
        '00 00 49 0a'
        '00 06 01 01'
        '08 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 28'.replace(' ', '')
    )
    reference_get_request_raw = hex2raw(reference_get_request_hex)

    reference_get_response_hex = (
        '00 00 29 0a'
        '00 06 01 01'
        '00 08 00 50'
        '4d 43 53 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 00'
        '00 00 00 28'.replace(' ', '')
    )
    reference_get_response_raw = hex2raw(reference_get_response_hex)

    def test_omci_frame_serialization(self):

        frame = OmciFrame(
            transaction_id=0,
            message_type=OmciGet.message_id,
            omci_message=OmciGet(
                entity_class=CircuitPack.class_id,
                entity_id=0x101,
                attributes_mask=CircuitPack.mask_for('vendor_id')
            )
        )
        self.assertEqual(hexify(str(frame)), self.reference_get_request_hex)

    def test_omci_frame_deserialization_no_data(self):
        frame = OmciFrame(self.reference_get_request_raw)
        self.assertEqual(frame.transaction_id, 0)
        self.assertEqual(frame.message_type, 0x49)
        self.assertEqual(frame.omci, 10)
        self.assertEqual(frame.omci_message.entity_class, 0x6)
        self.assertEqual(frame.omci_message.entity_id, 0x101)
        self.assertEqual(frame.omci_message.attributes_mask, 0x800)
        self.assertEqual(frame.omci_trailer, 0x28)

    def test_omci_frame_deserialization_with_data(self):
        frame = OmciFrame(self.reference_get_response_raw)
        self.assertEqual(frame.transaction_id, 0)
        self.assertEqual(frame.message_type, 0x29)
        self.assertEqual(frame.omci, 10)
        self.assertEqual(frame.omci_message.success_code, 0x0)
        self.assertEqual(frame.omci_message.entity_class, 0x6)
        self.assertEqual(frame.omci_message.entity_id, 0x101)
        self.assertEqual(frame.omci_message.attributes_mask, 0x800)
        self.assertEqual(frame.omci_trailer, 0x28)

    def test_entity_attribute_deserialization(self):
        pass


class TestSelectMessageGeneration(TestCase):

    def assertGeneratedFrameEquals(self, frame, ref):
        assert isinstance(frame, Packet)
        serialized_hexified_frame = hexify(str(frame)).upper()
        ref = ref.upper()
        if serialized_hexified_frame != ref:
            self.fail('Mismatch:\nReference:\n{}\nGenerated (bad):\n{}'.format(
                ref, serialized_hexified_frame
            ))

    def test_mib_reset_message_serialization(self):
        ref = '00014F0A000200000000000000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=1,
            message_type=OmciMibReset.message_id,
            omci_message=OmciMibReset(
                entity_class=OntData.class_id
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gal_ethernet_profile(self):
        ref = '0002440A011000010030000000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=2,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GalEthernetProfile.class_id,
                entity_id=1,
                data=dict(
                    max_gem_payload_size=48
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_tcont_1(self):
        ref = '0003480A010680008000040000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            alloc_id=0x400
        )
        frame = OmciFrame(
            transaction_id=3,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id=0x8000,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_tcont_2(self):
        ref = '0004480A010680018000040100000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            alloc_id=0x401
        )
        frame = OmciFrame(
            transaction_id=4,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Tcont.class_id,
                entity_id=0x8001,
                attributes_mask=Tcont.mask_for(*data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_8021p_mapper_service_profile(self):
        ref = '0007440A00828000ffffffffffffffff' \
              'ffffffffffffffffffff000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=7,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=0x8000,
                data=dict(
                    tp_pointer=OmciNullPointer,
                    interwork_tp_pointer_for_p_bit_priority_0=OmciNullPointer,
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_service_profile(self):
        ref = '000B440A002D02010001008000140002' \
              '000f0001000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=11,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgeServiceProfile.class_id,
                entity_id=0x201,
                data=dict(
                    spanning_tree_ind=False,
                    learning_ind=True,
                    priority=0x8000,
                    max_age=20 * 256,
                    hello_time=2 * 256,
                    forward_delay=15 * 256,
                    unknown_mac_address_discard=True
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gem_port_network_ctp(self):
        ref = '000C440A010C01000400800003010000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=12,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemPortNetworkCtp.class_id,
                entity_id=0x100,
                data=dict(
                    port_id=0x400,
                    tcont_pointer=0x8000,
                    direction=3,
                    traffic_management_pointer_upstream=0x100
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_multicast_gem_interworking_tp(self):
        ref = '0011440A011900060104000001000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=17,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MulticastGemInterworkingTp.class_id,
                entity_id=0x6,
                data=dict(
                    gem_port_network_ctp_pointer=0x104,
                    interworking_option=0,
                    service_profile_pointer=0x1,
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_gem_inteworking_tp(self):
        ref = '0012440A010A80010100058000000000' \
              '01000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=18,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=GemInterworkingTp.class_id,
                entity_id=0x8001,
                data=dict(
                    gem_port_network_ctp_pointer=0x100,
                    interworking_option=5,
                    service_profile_pointer=0x8000,
                    interworking_tp_pointer=0x0,
                    gal_profile_pointer=0x1
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_8021p_mapper_service_profile(self):
        ref = '0016480A008280004000800100000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            interwork_tp_pointer_for_p_bit_priority_0=0x8001
        )
        frame = OmciFrame(
            transaction_id=22,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=Ieee8021pMapperServiceProfile.class_id,
                entity_id=0x8000,
                attributes_mask=Ieee8021pMapperServiceProfile.mask_for(
                    *data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_port_configuration_data(self):
        ref = '001A440A002F21010201020380000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=26,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=0x2101,
                data=dict(
                    bridge_id_pointer=0x201,
                    port_num=2,
                    tp_type=3,
                    tp_pointer=0x8000
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_vlan_tagging_filter_data(self):
        ref = '001F440A005421010400000000000000' \
              '00000000000000000000000000000000' \
              '100100000000000000000028'
        frame = OmciFrame(
            transaction_id=31,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=VlanTaggingFilterData.class_id,
                entity_id=0x2101,
                data=dict(
                    vlan_filter_0=0x0400,
                    forward_operation=0x10,
                    number_of_entries=1
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_extended_vlan_tagging_operation_configuration_data(self):
        ref = '0023440A00AB02020A04010000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=35,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=0x202,
                data=dict(
                    association_type=10,
                    associated_me_pointer=0x401
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_operation_configuration_data(self):
        ref = '0024480A00AB02023800810081000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        data = dict(
            input_tpid=0x8100,
            output_tpid=0x8100,
            downstream_mode=0,  # inverse of upstream
        )
        frame = OmciFrame(
            transaction_id=36,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=0x202,
                attributes_mask= \
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_1(self):
        ref = '0025480A00AB02020400f00000008200' \
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
        frame = OmciFrame(
            transaction_id=37,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=0x202,
                attributes_mask= \
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_set_extended_vlan_tagging_2(self):
        ref = '0026480A00AB02020400F00000008200' \
              'd000402f00000008200c000000000000' \
              '000000000000000000000028'
        data = dict(
            received_frame_vlan_tagging_operation_table=\
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
        frame = OmciFrame(
            transaction_id=38,
            message_type=OmciSet.message_id,
            omci_message=OmciSet(
                entity_class=\
                    ExtendedVlanTaggingOperationConfigurationData.class_id,
                entity_id=0x202,
                attributes_mask= \
                    ExtendedVlanTaggingOperationConfigurationData.mask_for(
                        *data.keys()),
                data=data
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_create_mac_bridge_port_configuration_data2(self):
        ref = '0029440A002F02010201010b04010000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=41,
            message_type=OmciCreate.message_id,
            omci_message=OmciCreate(
                entity_class=MacBridgePortConfigurationData.class_id,
                entity_id=0x201,
                data=dict(
                    bridge_id_pointer=0x201,
                    encapsulation_methods=0,
                    port_num=1,
                    port_priority=0,
                    port_path_cost=0,
                    port_spanning_tree_in=0,
                    lan_fcs_ind=0,
                    tp_type=11,
                    tp_pointer=0x401
                )
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)
        frame2 = OmciFrame(hex2raw(ref))
        self.assertEqual(frame2, frame)

    def test_mib_upload(self):
        ref = '00304D0A000200000000000000000000' \
              '00000000000000000000000000000000' \
              '000000000000000000000028'
        frame = OmciFrame(
            transaction_id=48,
            message_type=OmciMibUpload.message_id,
            omci_message=OmciMibUpload(
                entity_class=OntData.class_id
            )
        )
        self.assertGeneratedFrameEquals(frame, ref)

    def test_parsing_mib_upload_next_responses(self):
        refs = [
            '00042e0a000200000002000080000000000000000000000000000000000000000000000000000000000000283e0c62ee',
            '00052e0a0002000000050101f0002f2f0520202020202020202020202020202020202020200000000000002808523170',
            '00062e0a00020000000501010f80202020202020202020202020202020202020202000000000000000000028922568e4',
            '00072e0a0002000000050104f00030300120202020202020202020202020202020202020200000000000002812bfa77d',
            '00082e0a00020000000501040f802020202020202020202020202020202020202020000000000000000000282b03fcee',
            '00092e0a0002000000050180f000f8f80120202020202020202020202020202020202020200000000000002881e385a2',
            '000a2e0a00020000000501800f8020202020202020202020202020202020202020200000000000000000002888c5dbc2',
            '000b2e0a0002000000060101f0002f054252434d12345678000000000000000000000000000c00000000002895471f4a',
            '000c2e0a00020000000601010f004252434d0000000000000000000000000000000000000000000000000028742cbaea',
            '000d2e0a000200000006010100f820202020202020202020202020202020202020200000000000000000002846978475',
            '000e2e0a00020000000601010004000000000000000000000000000000000000000000000000000000000028a8403aea',
            '000f2e0a0002000000060104f00030014252434d12345678000000000000000000000000000c000000000028723cf2ae',
            '00102e0a00020000000601040f004252434d0000000000000000000000000000000000000000000000000028a958ebf8',
            '00112e0a000200000006010400f8202020202020202020202020202020202020202000000800000000000028424cc847',
            '00122e0a000200000006010400040000000000000000000000000000000000000000000000000000000000282bb79708',
            '00132e0a0002000000060180f000f8014252434d12345678000000000000000000000000000c0000000000287834e722',
            '00142e0a00020000000601800f004252434d000000000000000000000000000000000000000000000000002833d78834',
        ]
        for i, data in enumerate(refs):
            frame = OmciFrame(hex2raw(data))
            print 'Response', i
            frame.show()


if __name__ == '__main__':
    main()
