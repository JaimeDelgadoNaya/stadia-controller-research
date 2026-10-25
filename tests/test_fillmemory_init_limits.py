"""Synthetic/structural tests; no HID or original image in test fixtures."""
import unittest
from tools import audit_fillmemory_init_limits as m
from tools import audit_fillmemory_wrap_model as wrap
from tools import audit_fillmemory_dynamic_guard as guard


class SignedInitializerTests(unittest.TestCase):
    def test_expected_initializer_literals(self):
        self.assertEqual(m.INIT_LIMITS,
            (0x20002000,0x20016D08,0x20208000,0x20216FFF))
        self.assertEqual([r[3] for r in m.PAIRS],[0x70,0x74,0x78,0x7c])

    def test_initializer_intervals_cover_execution_controls(self):
        a,b,c,d=m.INIT_LIMITS
        for field in wrap.CONTROL_FIELDS:
            self.assertLessEqual(a,field)
            self.assertLessEqual(field,b)
            self.assertFalse(c<=field<=d)

    def test_guard_rejects_normal_but_wrapped_end_bypasses_comparisons(self):
        cases=m.model_initial_state()
        self.assertEqual(len(cases),2)
        for case in cases:
            self.assertTrue(case["normal_four_bytes_rejected_by_guard"])
            self.assertTrue(case["wrapped_prechecks_can_pass"])
            self.assertFalse(case["wrapped_length_rejected_by_guard_if_initialized"])
            self.assertTrue(case["wrapped_length_exceeds_loader_ram"])
            self.assertIn("UNKNOWN",case["can_finish_and_return_control"])
            self.assertEqual(case["execution_bypass"],"NOT DEMONSTRATED")

    def test_guard_with_different_dynamic_state_may_reject(self):
        field=wrap.CONTROL_FIELDS[0]
        count=wrap.wrap_length_for_end(field,0x2003)
        self.assertTrue(guard.guard_symbolic_model(
            field,count,(0x20000000,0x20016D08,0x1000,0x20216fff)))

    def test_unknown_values_are_not_automatically_measured(self):
        with self.assertRaisesRegex(ValueError,"exact original"):
            m.analyze(bytes(m.original.SIZE))


if __name__=="__main__":
    unittest.main()
