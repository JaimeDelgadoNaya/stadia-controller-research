"""Regression of phase48 original signed class-object lookup and method call."""
import unittest
from tools import audit_bruce_ep0_class_object_phase48 as a

class EP0ClassObject48(unittest.TestCase):
    def test_signed_double_dereference_not_assumed_runtime_value(self):
        self.assertEqual(a.BRIDGE_PINS[a.INDIRECT],("blx","r3"))
        self.assertEqual(a.BRIDGE_PINS[0x600D0BF6],("ldr","r3, [r3, #4]"))
        self.assertEqual(a.BRIDGE_PINS[0x600D0BF8],("ldr","r3, [r3, #4]"))
        self.assertEqual(a.pins_match(dict(a.BRIDGE_PINS)),len(a.BRIDGE_PINS))

    def test_mutation_of_indirect_dispatch_caught(self):
        rows=dict(a.BRIDGE_PINS)
        rows[0x600D0BF8]=("ldr","r3, [r3]")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.pins_match(rows)

    def test_original_source_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic bytes")

    def test_aligned_word_bounds(self):
        with self.assertRaisesRegex(ValueError,"aligned"):
            a.raw_word(b"12345678",a.BASE+1)

if __name__=="__main__":
    unittest.main()
