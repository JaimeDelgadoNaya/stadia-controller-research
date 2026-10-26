"""Synthetic conditional routing tests; no USB device or firmware writes."""
import unittest
from tools import audit_bruce_ep0_class10_bridge_phase45 as a


class Class10BridgeTests(unittest.TestCase):
    def test_signed_model_table_limits(self):
        self.assertEqual(a.route_symbolic(0xa1,0x7f)["stage"],"class10_r1_guard_reject")
        self.assertEqual(a.route_symbolic(0xa1,0x80)["dispatch"],0)
        self.assertEqual(a.route_symbolic(0xa1,0x81)["dispatch"],1)
        self.assertEqual(a.route_symbolic(0xa1,0x83)["dispatch"],3)
        self.assertEqual(a.route_symbolic(0xa1,0x84)["dispatch"],4)
        self.assertEqual(a.route_symbolic(0xa1,0x8c)["dispatch"],12)
        self.assertEqual(a.route_symbolic(0xa1,0x8d)["stage"],"handler_range_guard_reject")
        self.assertEqual(a.route_symbolic(0xa1,0xff)["stage"],"handler_range_guard_reject")

    def test_recipient_guard_distinguishes_device_and_interface(self):
        for t in (0x20,0x22,0xa0,0xa2):
            self.assertEqual(a.route_symbolic(t,0x83)["stage"],"recipient_guard_reject")
        for t in (0x21,0xa1):
            self.assertEqual(a.route_symbolic(t,0x83)["stage"],"table_dispatch")

    def test_matching_interface_is_required(self):
        self.assertEqual(a.route_symbolic(0x21,0x83,matching_interface=False)["stage"],
                         "interface_guard_reject")

    def test_class10_selection_is_only_conditional(self):
        self.assertEqual(a.route_symbolic(0x21,0x83,registered_class10=False)["stage"],
                         "class10_not_registered")

    def test_signed_sentinel_bypasses_second_stage(self):
        self.assertEqual(a.route_symbolic(0xa1,0x83,active_secondary=False)["stage"],
                         "signed_default_sentinel_guard")
        self.assertIsNone(a.route_symbolic(0xa1,0x83,active_secondary=False)["dispatch"])

    def test_invalid_request_byte_rejected(self):
        for b in (-1,256):
            with self.assertRaisesRegex(ValueError,"0..255"):
                a.route_symbolic(0x21,b)

    def test_r1_carries_request_byte_to_signed_dispatch(self):
        steps=a.prove_r1_continuity()
        self.assertIn("[R1+1]",steps[1]["effect"])
        self.assertEqual(steps[-1]["pc"],"0x60077370")

    def test_mutated_image_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"not an OEM image")


if __name__=="__main__":
    unittest.main()
