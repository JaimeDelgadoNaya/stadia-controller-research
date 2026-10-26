"""Synthetic identity/semantic guards for original signed callback init audit."""
import unittest
from tools import audit_bruce_class10_secondary_init_phase42 as p


class SecondaryInitTests(unittest.TestCase):
    def test_pc_relative_signed_literal(self):
        self.assertEqual(p.pc_literal_at(0x60073CE6, 0x13C),0x60073E24)

    def test_expected_global_alias_is_exact(self):
        self.assertEqual(p.GLOBAL_BASE_CANDIDATE + p.OFF_CALLBACK, 0x20009EF8)
        self.assertEqual(p.GLOBAL_BASE_CANDIDATE + p.OFF_CONTEXT, 0x20009EFC)

    def test_semantic_anchor_mutation_detected(self):
        self.assertTrue(p.check_pins(dict(p.PINS)))
        pins=dict(p.PINS)
        pins[0x60073CF4]=("str","r1, [r4, #4]")
        with self.assertRaisesRegex(ValueError,"drift"):
            p.check_pins(pins)

    def test_original_image_required(self):
        with self.assertRaisesRegex(ValueError,"SHA"):
            p.audit(b"fabricated binary")


if __name__=="__main__":
    unittest.main()
