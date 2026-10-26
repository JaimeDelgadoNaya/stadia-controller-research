"""Tests for phase 42 candidate-site provenance: safe synthetic fixtures only."""
import unittest
from types import SimpleNamespace

from tools import audit_bruce_secondary_alias_phase42 as p


class FakeInstruction:
    def __init__(self, pc, mnemonic, op, writes=()):
        self.address = pc
        self.mnemonic = mnemonic
        self.op_str = op
        self._writes = writes

    def reg_name(self, reg):
        return reg

    def regs_access(self):
        return ((), tuple(self._writes))


class Phase42Tests(unittest.TestCase):
    def test_list_covers_nine_phase41_unresolved_sites(self):
        self.assertEqual(len(p.SITES), 9)
        self.assertEqual(len(set(p.SITES)), 9)
        self.assertEqual(set(p.BASE_REGISTERS), set(p.SITES))
        self.assertEqual(set(p.OFFSETS), set(p.SITES))

    def test_basic_block_cuts_at_branch(self):
        rows = [
            FakeInstruction(0x100, "ldr", "r3, [r7, #0x14]", ("r3",)),
            FakeInstruction(0x102, "bne", "#0x110"),
            FakeInstruction(0x104, "mov", "r2, r0", ("r2",)),
            FakeInstruction(0x106, "str.w", "r2, [r3, #0xf8]"),
        ]
        prev, target = p.basic_window(rows, 0x106)
        self.assertEqual([x.address for x in prev], [0x104])
        self.assertEqual(target.address, 0x106)
        self.assertIsNone(p.last_writer(prev, "r3"))

    def test_local_register_last_writer_is_not_entry_provenance(self):
        rows = [FakeInstruction(0x100, "ldr", "r3, [r7, #0x14]", ("r3",))]
        first = p.last_writer(rows, "r3")
        self.assertIn("ldr", first["instruction"])
        self.assertEqual(p.origin_class(first),
                         "loaded_through_other_pointer; no resolved absolute base")

    def test_no_base_definition_does_not_claim_target(self):
        self.assertEqual(p.origin_class(None), "unknown_entry_or_predecessor")
        self.assertIsNone(p.last_writer([FakeInstruction(0x10, "mov", "r2, r3", ("r2",))], "r3"))

    def test_constructor_direct_call_semantics_change_is_detected(self):
        self.assertTrue(p.check_constructor_pins(dict(p.CONSTRUCTOR_PINS)))
        alt=dict(p.CONSTRUCTOR_PINS)
        alt[0x60058920] = ("mov", "r0, r7")
        with self.assertRaisesRegex(ValueError, "drift"):
            p.check_constructor_pins(alt)

    def test_wrong_original_image_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            p.audit(b"synthetic")

    def test_unlisted_site_rejected(self):
        with self.assertRaisesRegex(ValueError, "unlisted"):
            p.inspect_site(b"", 0x60041234)


if __name__ == "__main__":
    unittest.main()
