import unittest
from tools import audit_app_usb_dispatch as audit


class ApplicationDispatchTests(unittest.TestCase):
    def test_itcm_mapping_and_bounds(self):
        self.assertEqual(audit.itcm_runtime(0x29BC), 0x21A0)
        self.assertEqual(audit.itcm_runtime(0xBE2C), 0xB610)
        for offset in [0x81B, 0x81C + 0xBDF8]:
            with self.assertRaises(ValueError):
                audit.itcm_runtime(offset)

    def test_callback_data_mapping(self):
        self.assertEqual(audit.initialized_ram(0xFE058), 0x200031F0)
        with self.assertRaises(ValueError):
            audit.initialized_ram(audit.DATA_SOURCE_OFFSET - 1)

    def test_wrong_runtime_target_is_rejected(self):
        decoded = dict(audit.ANCHORS)
        audit.validate_semantics(decoded)
        decoded[0x21F8] = ('bl', '#0x6004be2c')
        with self.assertRaises(ValueError):
            audit.validate_semantics(decoded)

    def test_other_image_is_rejected(self):
        with self.assertRaises(ValueError):
            audit.inspect(b'not firmware')


if __name__ == '__main__':
    unittest.main()
