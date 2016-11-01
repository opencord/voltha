from unittest import TestCase, main
from voltha.extensions.omci.omci import CirtcuitPackEntity, bitpos_from_mask
from voltha.extensions.omci.omci import EntityClass


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

        e = CirtcuitPackEntity(vendor_id='F')
        self.assertEqual(e.serialize(), 'F\x00\x00\x00')

        e = CirtcuitPackEntity(vendor_id='FOOX')
        self.assertEqual(e.serialize(), 'FOOX')

        e = CirtcuitPackEntity(vendor_id='FOOX', number_of_ports=16)
        self.assertEqual(e.serialize(), '\x10FOOX')


if __name__ == '__main__':
    main()
