"""Phase50 original USB owner trace safety and mutation tests."""
import unittest
from tools import audit_bruce_usb_owner_survey_phase50 as a
class OwnerSurvey50(unittest.TestCase):
    def test_owner_is_dynamic_and_mode2_guarded(self):
        self.assertEqual(a.KNOWN[0x60061020],("cmp","r5, #2"))
        self.assertEqual(a.KNOWN[0x6006102E],("bl","#0x60060f84"))
        self.assertEqual(a.KNOWN[0x60060F8A],("adds","r1, r0, #4"))
    def test_no_false_code_assumptions(self):
        self.assertEqual(a.validate_pins(dict(a.KNOWN)),len(a.KNOWN))
        x=dict(a.KNOWN);x[0x60061020]=("cmp","r5, #3")
        with self.assertRaisesRegex(ValueError,"drift"):a.validate_pins(x)
    def test_exact_original_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):a.audit(b"synthetic")
if __name__=="__main__": unittest.main()
