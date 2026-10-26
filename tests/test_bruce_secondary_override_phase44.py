"""Phase44 regressions for signed second callback pair and PC literal addressing."""
import unittest
from tools import audit_bruce_secondary_override_phase44 as a

class SecondWriterTests(unittest.TestCase):
    def test_pc_relative_addresses(self):
        self.assertEqual(a.literal_pc(0x600771EE,0xF4),0x600772E4)
        self.assertEqual(a.literal_pc(0x600771F0,0xF4),0x600772E8)

    def test_expected_callback_offsets(self):
        self.assertEqual(a.GLOBAL + a.OFFSET_FUNCTION,0x20009EF8)
        self.assertEqual(a.GLOBAL + a.OFFSET_CONTEXT,0x20009EFC)

    def test_orig_signed_semantic_guards(self):
        self.assertTrue(a.check_pins(dict(a.PINS)))
        mutation=dict(a.PINS)
        mutation[a.PC_WRITE_FUNCTION]=("ldr","r1, [r3, r2]")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.check_pins(mutation)

    def test_original_13_case_dispatch_table_is_pinned(self):
        self.assertEqual(len(a.EXPECTED_TBB), 13)
        self.assertTrue(a.validate_signed_dispatch_table(a.EXPECTED_TBB))
        self.assertEqual(a.TBB_BASE + 2 * a.EXPECTED_TBB[1], 0x60077392)
        self.assertEqual(a.TBB_BASE + 2 * a.EXPECTED_TBB[3], 0x600773A4)
        self.assertEqual(a.TBB_BASE + 2 * a.EXPECTED_TBB[4], 0x600773AE)
        invalid=bytearray(a.EXPECTED_TBB)
        invalid[3]^=1
        with self.assertRaisesRegex(ValueError,"drift"):
            a.validate_signed_dispatch_table(bytes(invalid))

    def test_wrong_original_file_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

if __name__=="__main__":
    unittest.main()
