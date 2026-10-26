"""Phase48: signed singleton class method initialization provenance guardrails."""
import unittest
from tools import audit_bruce_class_singleton_phase48 as a

class ClassSingleton48Tests(unittest.TestCase):
    def test_record_table_and_runtime_record_are_distinct(self):
        self.assertNotEqual(a.STATIC_TABLE_CLASS10,a.BOOT_CLASS10_RAM_RECORD)
        self.assertEqual(a.EP0_LOOKUP_GLOBAL,0x20004080)
        self.assertEqual(a.CLASS1_GLOBAL,0x200040c0)
        self.assertEqual(a.CLASS10_GLOBAL,0x200040e0)
        self.assertNotEqual(a.CLASS1_GLOBAL,a.CLASS10_GLOBAL)
        self.assertNotEqual(a.EP0_LOOKUP_GLOBAL,a.CLASS1_GLOBAL)
        self.assertNotEqual(a.EP0_LOOKUP_GLOBAL,a.CLASS10_GLOBAL)
        self.assertEqual(a.PINS[0x6005530A],("str","r6, [r4, #4]"))
        self.assertEqual(a.PINS[0x6005533A],("str","r6, [r4, #4]"))
        self.assertEqual(a.PINS[0x60055340],("str","r4, [r5]"))
        self.assertEqual(a.PINS[0x60055194],("blx","r3"))

    def test_hypothetical_record_alias_is_not_code_execution_proof(self):
        x=a.signed_12byte_record_impact()
        self.assertFalse(x["can_treat_that_as_signed_Thumb_method"])
        self.assertEqual(x["selected_record_pointer"],"0x200030f4")
        self.assertEqual(x["runtime_record_second_word_before_class_init"],"0x0")

    def test_drift_detection(self):
        x=dict(a.PINS)
        self.assertEqual(a.assert_original_pins(x),len(x))
        x[0x60055190]=("adds","r2, r1, #8")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.assert_original_pins(x)

    def test_reject_not_original_oem_file(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")

if __name__=="__main__":
    unittest.main()
