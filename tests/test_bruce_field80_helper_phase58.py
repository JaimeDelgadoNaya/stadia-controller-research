"""Phase 58 regression: fail-closed original signed helper and callsite audit."""
import unittest
from tools import audit_bruce_field80_helper_phase58 as m


class Phase58SignedHelper(unittest.TestCase):
    def test_two_original_read_path_calls(self):
        self.assertEqual(m.CALLS,(0x6007E7FA,0x6007E81E))
        self.assertEqual(m.HELPER,0x600D54B8)

    def test_exact_hash_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(b"invalid")

    def test_original_call_pins_not_other_helpers(self):
        self.assertNotEqual(m.HELPER,0x600D54F2)
        self.assertEqual(len(m.WINDOWS),5)

    def test_decode_excludes_short_buffer(self):
        with self.assertRaises((ValueError,IndexError)):
            m.pinpoint(b"bad",m.CALLS[0])


if __name__=="__main__":
    unittest.main()
