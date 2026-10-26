"""Phase 58 regression: fail-closed original signed helper and callsite audit."""
import unittest
from tools import audit_bruce_field80_helper_phase58 as m


class Phase58SignedHelper(unittest.TestCase):
    def test_two_original_read_path_calls(self):
        self.assertEqual(m.CALLS,(0x6007E7FA,0x6007E81E))
        self.assertEqual(m.HELPER,0x600D54B8)

    def test_forwarded_original_R0_is_not_direct_callee_argument(self):
        res=m.modeled_helper_forward(0xAAAA,0xBBBB,0xCCCC)
        self.assertEqual(res["backend_r0"],0xBBBB)
        self.assertEqual(res["backend_r1"],0xCCCC)
        self.assertFalse(res["incoming_r0_forwarded_directly"])

    def test_six_signed_adapter_instructions(self):
        self.assertEqual(len(m.HELPER_PINS),6)
        self.assertEqual(m.HELPER_PINS[0x600D54C6],("b.w","#0x6006386c"))

    def test_backend_pair_stores_are_distinct_offsets(self):
        self.assertEqual(m.BACKEND_PINS[0x60063878],("str.w","r2, [r3, #0x37c]"))
        self.assertEqual(m.BACKEND_PINS[0x6006387E],("str.w","r2, [r3, #0x380]"))
        self.assertEqual(len(m.BACKEND_PINS),10)

    def test_reject_unaligned_literal(self):
        with self.assertRaisesRegex(ValueError,"unaligned"):
            m.signed_word(b"invalid",m.BASE+3)

    def test_thumb_function_target_regions(self):
        self.assertEqual(m.classify_signed_thumb_code_pointer(0x600CE233),"SIGNED_XIP_CODE_CANDIDATE")
        self.assertEqual(m.classify_signed_thumb_code_pointer(0x0000A9C5),"SIGNED_STARTUP_RELOCATED_ITCM_CODE_CANDIDATE")
        self.assertEqual(m.classify_signed_thumb_code_pointer(0x600CE232),"NOT_THUMB_CODE_POINTER")

    def test_reject_altered_callback_like_pointers(self):
        with self.assertRaisesRegex(ValueError,"literal drift"):
            m.verify_signed_callback_entries(b"not original",0x600CE231,0xA9C5)

    def test_exact_hash_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(b"invalid")

    def test_original_call_pins_not_other_helpers(self):
        self.assertNotEqual(m.HELPER,0x600D54F2)
        self.assertEqual(len(m.WINDOWS),7)

    def test_decode_excludes_short_buffer(self):
        with self.assertRaises((ValueError,IndexError)):
            m.pinpoint(b"bad",m.CALLS[0])


if __name__=="__main__":
    unittest.main()
