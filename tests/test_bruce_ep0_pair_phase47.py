"""Synthetic regression for signed dedicated EP0 pair installer."""
import unittest
from tools import audit_bruce_ep0_pair_phase47 as a

class DedicatedEP0Pair47(unittest.TestCase):
    def test_original_literal_addresses(self):
        self.assertEqual(a.literal_at(0x60054F32,0x40),0x60054F74)
        self.assertEqual(a.literal_at(0x60054F3E,0x38),0x60054F78)

    def test_signed_callback_registration_pair_and_rollback_anchors(self):
        self.assertEqual(a.PIN[0x60054F4A],("bl","#0x600d10b8"))
        self.assertEqual(a.PIN[0x60054F5C],("bl","#0x600d10b8"))
        self.assertEqual(a.PIN[0x60054F52],("strb.w","r0, [sp, #6]"))
        self.assertEqual(a.PIN[0x60054F64],("movs","r1, #0x80"))
        self.assertEqual(a.PIN[0x60054F68],("bl","#0x600d10f6"))
        self.assertEqual(a.validate_pins(dict(a.PIN)),len(a.PIN))

    def test_original_installer_mutation_rejected(self):
        mutated=dict(a.PIN)
        mutated[a.SECOND_REG]=("bl","#0x600d10f6")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.validate_pins(mutated)

    def test_runtime_endpoint_indexing_examples(self):
        self.assertEqual(a.endpoint_index(0x80),1)
        self.assertEqual(a.endpoint_index(0x00),0)

    def test_signed_image_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic input")

if __name__=="__main__":
    unittest.main()
