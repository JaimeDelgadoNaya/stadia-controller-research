"""Synthetic semantic regression tests for original Bruce class loop provenance."""
import unittest
from tools import audit_bruce_class_selector_verified as x
class SelectorPinsTests(unittest.TestCase):
    def test_missing_signed_image_rejected(self):
        with self.assertRaisesRegex(ValueError,"exact original"):
            x.audit(bytes(x.IMAGE_SIZE))
    def test_pc_thumb_alignment(self):
        self.assertEqual(x.literal_address(0x60055142,0x70),0x600551B4)
        self.assertEqual(x.literal_address(0x600551CC,0x50),0x60055220)
    def test_two_loop_strides_and_indirect_calls(self):
        self.assertEqual(x.PINS[0x60055196],("adds","r7, #0x10"))
        self.assertEqual(x.PINS[0x60055198],("cmp","r7, #0x50"))
        self.assertEqual(x.PINS[0x60055216],("adds","r6, #0x10"))
        self.assertEqual(x.PINS[0x60055218],("cmp","r6, #0x50"))
        self.assertEqual(x.PINS[0x60055194],("blx","r3"))
        self.assertEqual(x.PINS[0x60055214],("blx","r2"))
    def test_drift_rejected(self):
        rows=dict(x.PINS)
        rows[0x60055198]=("cmp","r7, #0x60")
        with self.assertRaisesRegex(ValueError,"drift"):
            x.verify_pins(rows)
if __name__=="__main__":
    unittest.main()
