"""Phase51 guard real signed owner-status instructions and R0 vs R2 distinction."""
import unittest
from tools import audit_bruce_owner_mode_guards_phase51 as a
class Mode51(unittest.TestCase):
    def test_owner_status_and_config_offsets_distinct(self):
        self.assertEqual(a.PINS[0x600D4E66],("ldr.w","r3, [r0, #0x90]"))
        self.assertEqual(a.PINS[0x600D551A],("ldrb.w","r3, [r0, #0x104]"))
        self.assertEqual(a.PINS[0x60060FEC],("ldr.w","r3, [r0, #0x90]"))
    def test_owner_as_r2_not_r0_in_separate_constructor(self):
        self.assertEqual(a.PINS[0x60079D7C],("ldr","r2, [pc, #0x54]"))
        self.assertEqual(a.PINS[0x6007EBA6],("strd","r5, r5, [r0, #4]"))
    def test_reject_signed_anchor_drift(self):
        self.assertEqual(a.pin_original(dict(a.PINS)),len(a.PINS))
        changed=dict(a.PINS)
        changed[0x60079D7C]=("ldr","r0, [pc, #0x54]")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.pin_original(changed)
    def test_oem_input_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")
if __name__=="__main__":unittest.main()
