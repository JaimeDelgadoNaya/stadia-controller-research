"""Phase 55 signed-owner holder provenance model regression tests."""
import struct
import unittest

from tools import audit_bruce_owner_holder_phase55 as a


class Phase55OwnerHolder(unittest.TestCase):
    def test_signed_owner_in_R2_is_not_parent_R0(self):
        r = a.propagate_holder(a.OWNER)
        self.assertEqual(r["value"], "0x2000a2a8")
        self.assertEqual(r["holder_field_offset"], 0x80)
        self.assertEqual(r["absolute_address"], "UNKNOWN")

    def test_unknown_argument_remains_unknown(self):
        r = a.propagate_holder(None)
        self.assertEqual(r["absolute_address"], "UNKNOWN")
        self.assertEqual(r["value"], "UNKNOWN")

    def test_callee_saved_register_holds_original_owner_pointer(self):
        r = a.propagate_holder(a.OWNER, saved_r8=a.OWNER)
        self.assertEqual(r["value"], hex(a.OWNER))

    def test_separate_method_field(self):
        self.assertEqual(a.CFG_METHOD, 0x2000A2B0)
        self.assertNotEqual(a.CFG_METHOD, a.OWNER + a.HOLDER_FIELD_OFFSET)

    def test_group_pointer_not_owner(self):
        self.assertEqual(a.GROUP, 0x200030E8)
        self.assertNotEqual(a.GROUP, a.OWNER)

    def test_thumb_pc_relative_literal_base(self):
        self.assertEqual(a.pc_literal_address(0x60079D7C, 0x54), 0x60079DD4)
        self.assertEqual(a.pc_literal_address(0x600610FC, 0), 0x60061100)
        self.assertEqual(a.pc_literal_address(0x60061104, 0), 0x60061108)

    def test_real_signed_literal_alignment_from_synthetic(self):
        synthetic = bytearray(0x22000)
        struct.pack_into("<I", synthetic, 0x61100 - 0x40000, a.GROUP)
        self.assertEqual(a.read_word(synthetic, 0x60061100), a.GROUP)
        with self.assertRaisesRegex(ValueError, "unaligned"):
            a.read_word(synthetic, 0x60061101)

    def test_different_owner_literal_cannot_pass_check(self):
        fake = bytearray(0x40000)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            a.audit(fake)

    def test_original_pins_fails_closed_without_oem(self):
        with self.assertRaises(ValueError):
            a.validate_original(b"synthetic")

    def test_caller_must_keep_r2_through_callsite(self):
        self.assertEqual(a.PINS[0x60079D7C], ("ldr", "r2, [pc, #0x54]"))
        self.assertEqual(a.PINS[0x60079D84], ("bl", "#0x6007eb8c"))
        self.assertEqual(a.PINS[0x6007EB9E], ("mov", "r8, r2"))
        self.assertEqual(a.PINS[0x6007EBB4], ("str.w", "r8, [r4, #0x80]"))


if __name__ == "__main__":
    unittest.main()
