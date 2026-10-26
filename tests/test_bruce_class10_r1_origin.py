"""Synthetic semantics and image identity tests for signed class10 R1 trace."""
import unittest
from tools import audit_bruce_class10_r1_origin as a

class SignedR1Tests(unittest.TestCase):
    def test_exact_oem_image_required(self):
        with self.assertRaisesRegex(ValueError, "Exactly pinned"):
            a.audit(bytes(a.IMAGE_SIZE))
    def test_offset_and_stride_math(self):
        self.assertEqual(a.origin_equation(0,0x20001000),0x20001000)
        self.assertEqual(a.origin_equation(3,0x20001000),0x20001024)
        with self.assertRaises(ValueError):
            a.origin_equation(256,0x20001000)
    def test_provenance_anchors(self):
        self.assertTrue(a.check_r1_pins(dict(a.R1_PROVENANCE_PINS)))
        self.assertEqual(a.R1_PROVENANCE_PINS[0x6005512E],("str","r4, [r5, #4]"))
        self.assertEqual(a.R1_PROVENANCE_PINS[0x60055180],("add","r1, r8"))
        self.assertEqual(a.R1_PROVENANCE_PINS[0x6005533A],("str","r6, [r4, #4]"))
    def test_semantic_drift_fails(self):
        p=dict(a.R1_PROVENANCE_PINS)
        p[0x60055180]=("add","r1, r2")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.check_r1_pins(p)

if __name__=="__main__":
    unittest.main()
