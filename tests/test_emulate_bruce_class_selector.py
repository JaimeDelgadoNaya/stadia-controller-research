"""Synthetic-only tests for signed Bruce class selector emulator."""
import unittest
from tools import emulate_bruce_class_selector as m
class SyntheticClassSelectorTests(unittest.TestCase):
    def test_requires_exact_oem_image(self):
        with self.assertRaisesRegex(ValueError,"Exact original"):
            m.audit(bytes(m.IMAGE_SIZE))
    def test_index_and_stop_address(self):
        self.assertEqual(m.ENTRY_PC,0x60055178)
        self.assertEqual(m.MATCH_PC,0x60055194)
        self.assertEqual(m.NO_MATCH_PC,0x60055196)
    def test_synthetic_inputs_guarded(self):
        with self.assertRaises(ValueError):
            m.synthetic_case(b"",5,10)
        with self.assertRaises(ValueError):
            m.synthetic_case(b"",3,256)
if __name__=="__main__":
    unittest.main()
