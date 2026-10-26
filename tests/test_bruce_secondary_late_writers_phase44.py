"""Phase44: synthetic guardrails for original signed secondary offset-builder census."""
import struct
import unittest

from tools import audit_bruce_secondary_late_writers_phase44 as a


class SecondaryLateWriterTests(unittest.TestCase):
    def test_required_original_offset_alias(self):
        self.assertEqual(a.OFF_CALLBACK,0x3A38)
        self.assertEqual(a.OFF_CONTEXT,0x3A3C)
        self.assertEqual(a.GLOBAL_BASE_CANDIDATE+a.OFF_CALLBACK,0x20009EF8)
        self.assertEqual(a.GLOBAL_BASE_CANDIDATE+a.OFF_CONTEXT,0x20009EFC)

    def test_movw_thumb32_screen_excludes_movt(self):
        self.assertTrue(a.movw_encoding_candidate(0xF643))
        self.assertFalse(a.movw_encoding_candidate(0xF2C0))

    def test_decode_synthetic_movw_r3_3a38(self):
        # MOVW R3,#0x3a38: real Thumb-2 little-endian halfwords.
        instr=struct.pack("<HH",0xF643,0x2338)
        result=a.decode_movw(a.md_thumb(),instr,0,0x60080000)
        self.assertIsNotNone(result)
        self.assertEqual(result["constant"],a.OFF_CALLBACK)
        self.assertEqual(result["reg"],"r3")

    def test_wrong_image_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

    def test_non_movw_does_not_become_candidate(self):
        result=a.decode_movw(a.md_thumb(),struct.pack("<HH",0xBF00,0xBF00),
                             0,0x60080000)
        self.assertIsNone(result)


if __name__=="__main__":
    unittest.main()
