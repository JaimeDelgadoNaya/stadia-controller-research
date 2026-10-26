"""Phase49 signed USB configuration provenance guards; synthetic only."""
import unittest
from tools import audit_bruce_runtime_usb_config_phase49 as a

class RuntimeUSBConfig49(unittest.TestCase):
    def test_base_and_config_are_distinct(self):
        self.assertEqual(a.USB_CORE,0x20004080)
        self.assertNotEqual(a.USB_CORE,a.CLASS10_GLOBAL)
        self.assertEqual(a.USB_CORE+4,0x20004084)
    def test_bss_is_not_signed_initialised_data(self):
        self.assertEqual(a.source_for_ram(a.USB_CORE)["file_offset"],None)
        self.assertEqual(a.source_for_ram(a.USB_CORE)["kind"].startswith("NOT IN"),True)
        self.assertEqual(a.source_for_ram(a.DATA_DESTINATION)["file_offset"],hex(a.DATA_SOURCE_OFFSET))
    def test_exact_binary_is_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.inspect(b"synthetic")
if __name__=="__main__":
    unittest.main()
