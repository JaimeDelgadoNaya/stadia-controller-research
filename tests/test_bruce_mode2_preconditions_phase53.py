"""Phase 53: necessary USB mode-2 signed-code guard regressions.

Synthetic guard tests cannot establish physical reachability or live RAM.
"""
import unittest
from tools import audit_bruce_mode2_preconditions_phase53 as a


class Mode2Preconditions(unittest.TestCase):
    def test_zero_previous_mode_blocks_even_if_mode2_is_requested(self):
        self.assertFalse(a.necessary_mode2_guard(0, 2))

    def test_same_previous_mode_blocks_duplicate_transition(self):
        self.assertFalse(a.necessary_mode2_guard(2, 2))

    def test_nonzero_different_modes_pass_only_early_guards(self):
        self.assertTrue(a.necessary_mode2_guard(1, 2))
        self.assertTrue(a.necessary_mode2_guard(3, 2))
        self.assertTrue(a.necessary_mode2_guard(4, 2))

    def test_requested_non_mode2_never_passes_mode2_gate(self):
        for requested in (0, 1, 3, 4):
            self.assertFalse(a.necessary_mode2_guard(3, requested))

    def test_negative_modes_rejected(self):
        with self.assertRaises(ValueError):
            a.necessary_mode2_guard(-1, 2)
        with self.assertRaises(ValueError):
            a.necessary_mode2_guard(1, -2)

    def test_zero_method_rejected_but_nonzero_only_necessary(self):
        self.assertFalse(a.method_guard(0))
        self.assertTrue(a.method_guard(1))
        self.assertTrue(a.method_guard(0x600550E5))
        for invalid in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                a.method_guard(invalid)

    def test_original_pin_drift_fail_closed_without_signed_file(self):
        with self.assertRaisesRegex(ValueError, "Phase53 original signed guard drift"):
            a.verify_original_pins(b"synthetic")

    def test_original_sha_required(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            a.audit(b"synthetic")

    def test_field_address_arithmetic(self):
        self.assertEqual(a.PREVIOUS_MODE_FIELD, 0x2000A338)
        self.assertEqual(a.OWNER + 8, 0x2000A2B0)

    def test_constructors_and_mode_transitions_distinguished(self):
        self.assertNotEqual(a.MODE2_CONSTRUCTOR, a.MODE_TRANSITION)
        self.assertEqual(a.PINS[0x6006102E], ("bl", "#0x60060f84"))
        self.assertEqual(a.PINS[0x60061070], ("str.w", "r5, [r4, #0x90]"))


if __name__ == "__main__":
    unittest.main()
