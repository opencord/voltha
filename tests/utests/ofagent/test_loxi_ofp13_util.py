from unittest import TestCase, main
import loxi.of13 as ofp

class TestConection_mgr(TestCase):

    def test_bitmap_to_version(self):
        bitmaps = [18]
        versions = ofp.util.bitmap_to_version(bitmaps)
        self.assertEqual(versions,[1,4])

if __name__ == '__main__':
    main()
