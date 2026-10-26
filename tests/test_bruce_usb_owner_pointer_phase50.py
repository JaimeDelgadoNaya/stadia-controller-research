"""Phase50 tests for original signed mode-2 path and owner pointer BSS provenance."""
import unittest
from tools import audit_bruce_usb_owner_pointer_phase50 as a
class OwnerPointer50(unittest.TestCase):
    def test_mode_2_branch_is_not_unconditional(self):
        self.assertEqual(a.PINS[0x6007142C],("moveq","r1, #2"))
        self.assertEqual(a.PINS[0x6007142E],("movne","r1, #1"))
        self.assertEqual(a.PINS[0x6006102A],("bne","#0x60061080"))
    def test_no_fake_runtime_class_count(self):
        self.assertGreater(a.OWNER,a.DATA_END)
        self.assertEqual(a.OWNER,0x2000A2A8)
        self.assertEqual(a.OWNER+4,0x2000A2AC)
        self.assertEqual(a.OWNER+12,0x2000A2B4)
    def test_signed_pin_mutation(self):
        self.assertEqual(a.verify(dict(a.PINS)),len(a.PINS))
        mutated=dict(a.PINS);mutated[0x60071416]=("ldr","r0, [pc, #0x24]")
        with self.assertRaisesRegex(ValueError,"drift"):a.verify(mutated)
    def test_bad_binary(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):a.audit(b"synthetic")
if __name__=="__main__":unittest.main()
