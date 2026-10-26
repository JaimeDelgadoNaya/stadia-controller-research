"""Phase57 synthetic alias checks and signed-image guards."""
import unittest
from tools import audit_bruce_parent_consumer_phase57 as a


class ParentConsumerPhase57(unittest.TestCase):
    def test_signed_post_constructor_call_anchor(self):
        self.assertEqual(a.CALLER_PINS[0x60079D96],("mov","r0, r4"))
        self.assertEqual(a.CALLER_PINS[0x60079D9A],("bl","#0x6007e784"))

    def test_reader_candidates_are_not_proven_same_object(self):
        self.assertEqual(len(a.READ_PINS),3)
        for m,op in a.READ_PINS.values():
            self.assertIsNotNone(a.offset_reader(m,op))

    def test_safe_local_register_propagation(self):
        rows=[{"pc":"0x100","m":"mov","op":"r4, r0"},
              {"pc":"0x102","m":"cmp","op":"r2, #0"},
              {"pc":"0x104","m":"str","op":"r3, [sp]"},
              {"pc":"0x106","m":"ldr","op":"r0, [r4, #0x80]"}]
        self.assertTrue(a.same_register_without_redefinition(rows,0x100,0x106,"r4"))

    def test_unknown_branch_prevents_proven_local_identity(self):
        rows=[{"pc":"0x100","m":"mov","op":"r4, r0"},
              {"pc":"0x102","m":"bne","op":"#0x110"},
              {"pc":"0x104","m":"ldr","op":"r0, [r4, #0x80]"}]
        self.assertFalse(a.same_register_without_redefinition(rows,0x100,0x104,"r4"))

    def test_call_prevents_proven_local_identity(self):
        rows=[{"pc":"0x100","m":"mov","op":"r4, r0"},
              {"pc":"0x102","m":"bl","op":"#0x60070000"},
              {"pc":"0x106","m":"ldr","op":"r0, [r4, #0x80]"}]
        self.assertFalse(a.same_register_without_redefinition(rows,0x100,0x106,"r4"))

    def test_register_redefinition_rejected(self):
        rows=[{"pc":"0x100","m":"mov","op":"r4, r0"},
              {"pc":"0x102","m":"mov","op":"r4, r1"},
              {"pc":"0x104","m":"ldr","op":"r0, [r4, #0x80]"}]
        self.assertFalse(a.same_register_without_redefinition(rows,0x100,0x104,"r4"))

    def test_post_init_wrapper_does_not_read_plus80(self):
        self.assertEqual(a.POST_INIT_WRAPPER_PINS[0x6007E784],("movs","r2, #0x1b"))
        self.assertEqual(a.POST_INIT_WRAPPER_PINS[0x6007E788],("adds","r0, #0xc"))
        self.assertEqual(a.POST_INIT_WRAPPER_PINS[0x6007E78A],("b.w","#0x6010177a"))
        self.assertTrue(all(not (x[0].startswith("ldr") and "#0x80" in x[1])
                            for x in a.POST_INIT_WRAPPER_PINS.values()))

    def test_separate_reader_entry_register_save(self):
        self.assertEqual(a.READER_ENTRIES["state_dispatch"][0x6007E79A],("mov","r4, r0"))
        self.assertEqual(a.READER_ENTRIES["later_dispatch"][0x6007E8B8],("mov","r4, r0"))
        self.assertEqual(len(a.XREF_TARGETS),3)

    def test_original_sha_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"not signed firmware")


if __name__=="__main__":
    unittest.main()
