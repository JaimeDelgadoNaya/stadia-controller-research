"""Synthetic guard test; does not load real firmware or access device."""
import unittest
from tools import emulate_bruce_class10_callback_guard as m

class Class10GuardTests(unittest.TestCase):
    def test_oem_sha_mandatory(self):
        with self.assertRaisesRegex(ValueError,"Exact signed OEM"):
            m.inspect(bytes(m.IMAGE_SIZE))
    def test_pointer_slots_within_virtual_ram(self):
        self.assertEqual(m.GLOBAL_CALLBACK_BASE+0x3A38,m.GLOBAL_CALLBACK_ADDR)
        self.assertEqual(m.GLOBAL_CALLBACK_BASE+0x3A3C,m.GLOBAL_CONTEXT_ADDR)
        self.assertEqual(m.EXEC_PC,0x600613FC)
        self.assertEqual(m.BEFORE_INDIRECT_BLX,0x60061416)
    def test_synthetic_input_constraints(self):
        with self.assertRaises(ValueError):
            m.case(b"",256,m.OTHER_SIGNED_CALLBACK)
        with self.assertRaises(ValueError):
            m.case(b"",0x81,0x20003001)
if __name__=="__main__":
    unittest.main()
