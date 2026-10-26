"""Phase49 synthetic and signed config pointer provenance regressions."""
import unittest
from tools import audit_bruce_usb_config_writer_phase49 as a
class SignedWriter49(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(a.ORIGINAL_LITERALS[0x600551A8],0x20004080)
        self.assertEqual(a.ORIGINAL_LITERALS[0x600551AC],0x200040A0)
        self.assertEqual(a.ORIGINAL_LITERALS[0x600551B0],0x600D0BC9)
        self.assertEqual(a.ORIGINAL_LITERALS[0x600553F8],0x200063C0)
        self.assertEqual(a.ORIGINAL_LITERALS[0x600553FC],0x60104BC4)
    def test_config_pointer_is_caller_ram_not_static_class_record(self):
        self.assertEqual(a.PINS[0x6005512E],("str","r4, [r5, #4]"))
        self.assertEqual(a.PINS[0x600550EA],("mov","r4, r1"))
        self.assertEqual(a.PINS[0x60060F8A],("adds","r1, r0, #4"))
        self.assertEqual(a.PINS[0x60060F90],("bl","#0x600550e4"))
    def test_synthetic_owner_layout(self):
        owner=0x20008000
        x=a.abstract_config_owner(owner)
        self.assertEqual(x["config_start"],hex(owner+4))
        self.assertEqual(x["dynamic_config_method_field"],hex(owner+8))
        self.assertEqual(x["class_record_count_byte"],hex(owner+12))
        self.assertEqual(x["engine_output_pointer_field"],hex(owner+0x98))
        with self.assertRaisesRegex(ValueError,"RAM owner"):
            a.abstract_config_owner(0x60000000)
    def test_original_engine_method_is_signed(self):
        self.assertEqual(a.PINS[0x600553C0],("str","r3, [r4, #4]"))
        self.assertEqual(a.PINS[0x600553C2],("str","r4, [r7]"))
        self.assertEqual(a.PINS[0x600553CA],("blx","r3"))
    def test_mutation(self):
        self.assertEqual(a.check_original_pins(dict(a.PINS)),len(a.PINS))
        changed=dict(a.PINS);changed[0x6005512E]=("str","r3, [r5, #4]")
        with self.assertRaisesRegex(ValueError,"drift"):a.check_original_pins(changed)
    def test_real_hash(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):a.audit(b"fake")
if __name__=="__main__":
    unittest.main()
