"""No-device synthetic regression for signed class10 case pinning."""
import unittest

from tools import audit_bruce_class10_case_effects_phase45 as p

class CaseEffects45Tests(unittest.TestCase):
    def test_key_cases_have_pinned_instructions(self):
        self.assertEqual(len(p.FOCUS_PINS),19)
        self.assertEqual(p.FOCUS_PINS[0x60077392],
                         ("add.w","r4, r0, #0x190"))
        self.assertEqual(p.FOCUS_PINS[0x600773A6],
                         ("add.w","r0, r0, #0x12c"))
        self.assertEqual(p.FOCUS_PINS[0x600773AE],
                         ("add.w","r4, r0, #0x1d8"))

    def test_case_81_and_84_write_return_like_buffer_from_context(self):
        self.assertIn("context_object",p.SUMMARY["0x81"]["signed_local_operation"])
        self.assertIn("context_object",p.SUMMARY["0x84"]["signed_local_operation"])
        self.assertFalse(p.SUMMARY["0x84"]["is_incoming_arbitrary_callback_address_store"])

    def test_8c_writes_signed_returns_to_context_not_direct_callback_slot(self):
        self.assertEqual(p.FOCUS_PINS[0x6007749E],("str.w","r0, [r4, #0x198]"))
        self.assertEqual(p.FOCUS_PINS[0x600774AA],("str","r0, [r4, #4]"))
        self.assertEqual(p.FOCUS_PINS[0x600774AC],("b","#0x60077396"))
        self.assertIn("signed",p.SUMMARY["0x8c"]["signed_local_operation"])

    def test_source_requires_oem_image(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"synthetic-bad-bytes")

if __name__=="__main__":
    unittest.main()
