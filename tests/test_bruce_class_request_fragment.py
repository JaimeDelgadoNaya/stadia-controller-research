"""Pure synthetic packet-format tests (no Unicorn, no OEM binary, no USB)."""
import unittest
from tools import emulate_bruce_class_request_fragment as m

class OriginalClassFragmentTests(unittest.TestCase):
    def test_class_interface_request(self):
        self.assertEqual(m.synthetic_packet(0x81,0xA1,1),bytes.fromhex("a181000001000000"))
        self.assertEqual(m.synthetic_packet(0x83,0x21,1),bytes.fromhex("2183000001000000"))
        self.assertEqual(m.synthetic_packet(0x84,0xA1,2),bytes.fromhex("a184000002000000"))
    def test_invalid_value_guard(self):
        for a,b,c in [(256,0xA1,1),(-1,0xA1,1),(0x81,256,1),(0x81,0xA1,-1)]:
            with self.assertRaises(ValueError):
                m.synthetic_packet(a,b,c)
    def test_requires_original_signed_image(self):
        with self.assertRaisesRegex(ValueError,"exact original"):
            m.emulate(bytes(m.IMAGE_SIZE))
    def test_no_hardware_surfaces_in_code(self):
        self.assertEqual(m.EXEC_START,0x600D0EA2)
        self.assertEqual(m.EXEC_DISPATCH,0x600D0EBE)
        self.assertEqual(m.DUMMY_CALLBACK,0x20003001)
if __name__=="__main__":
    unittest.main()
