from unittest import TestCase, main

from hexdump import hexdump

from voltha.extensions.omci.omci import CircuitPackEntity, bitpos_from_mask, \
    OmciUninitializedFieldError, OMCIGetResponse, OMCIFrame, OMCIGetRequest
from voltha.extensions.omci.omci import EntityClass


def hexify(buffer):
    """Return a hexadecimal string encoding of input buffer"""
    return ''.join('%02x' % ord(c) for c in buffer)


def chunk(indexable, chunk_size):
    for i in range(0, len(indexable), chunk_size):
        yield indexable[i : i + chunk_size]


def hex2raw(hex_string):
    return ''.join(chr(int(byte, 16)) for byte in chunk(hex_string, 2))


class TestOmci(TestCase):

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

        e = CircuitPackEntity(vendor_id='F')
        self.assertEqual(e.serialize(), 'F\x00\x00\x00')

        e = CircuitPackEntity(vendor_id='FOOX')
        self.assertEqual(e.serialize(), 'FOOX')

        e = CircuitPackEntity(vendor_id='FOOX', number_of_ports=16)
        self.assertEqual(e.serialize(), '\x10FOOX')

    def test_entity_attribute_serialization_mask_based(self):

        e = CircuitPackEntity(
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
        cls = CircuitPackEntity
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

        frame = OMCIFrame(
            transaction_id=0,
            message_type=0x49,
            omci_message=OMCIGetRequest(
                entity_class=CircuitPackEntity.class_id,
                entity_id=0x101,
                attributes_mask=CircuitPackEntity.mask_for('vendor_id')
            )
        )
        self.assertEqual(hexify(str(frame)), self.reference_get_request_hex)

    def test_omci_frame_deserialization_no_data(self):
        frame = OMCIFrame(self.reference_get_request_raw)
        self.assertEqual(frame.transaction_id, 0)
        self.assertEqual(frame.message_type, 0x49)
        self.assertEqual(frame.omci, 10)
        self.assertEqual(frame.omci_message.entity_class, 0x6)
        self.assertEqual(frame.omci_message.entity_id, 0x101)
        self.assertEqual(frame.omci_message.attributes_mask, 0x800)
        self.assertEqual(frame.omci_trailer, 0x28)

    def test_omci_frame_deserialization_with_data(self):
        frame = OMCIFrame(self.reference_get_response_raw)
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

if __name__ == '__main__':
    main()
