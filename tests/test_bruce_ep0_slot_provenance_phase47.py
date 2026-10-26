"""Pure synthetic endpoint descriptor guards and original signed-code pins."""
import unittest
from tools import audit_bruce_ep0_slot_provenance_phase47 as a

class EP0SlotProvenance47(unittest.TestCase):
    def test_ep0_out_never_selects_event1_adapter_from_caller_a(self):
        for flags in range(256):
            self.assertNotEqual(a.select_a(0x00,flags),"type1")

    def test_ep0_in_event1_requires_three_guard_conditions(self):
        self.assertEqual(a.select_a(0x80,0x01),"type1")
        self.assertEqual(a.select_a(0x80,0x11),"type2")
        self.assertEqual(a.select_a(0x80,0x03),"type3")
        self.assertEqual(a.select_a(0x00,0x01),"type3")
        self.assertEqual(a.select_a(0x81,0x01),"type1")

    def test_second_descriptor_caller_only_registers_qualifying_in(self):
        self.assertEqual(a.select_b(0x80,0x03),"type4")
        self.assertIsNone(a.select_b(0x00,0x03))
        self.assertIsNone(a.select_b(0x80,0x01))

    def test_signed_record_has_same_slot_address_calculation_as_receiver(self):
        out=a.symbolic_registration(0x00,0x00,caller="A")
        self.assertEqual(out["slot_index"],0)
        self.assertEqual(out["slot_function_field_offset"],"0xc")
        self.assertEqual(out["slot_context_field_offset"],"0x10")
        inp=a.symbolic_registration(0x80,0x01,caller="A")
        self.assertEqual(inp["slot_index"],1)
        self.assertEqual(inp["slot_function_field_offset"],"0x18")
        self.assertEqual(inp["signed_adapter"],"0x600cfc35")
        self.assertEqual(inp["internal_event_tag"],1)

    def test_no_registration_when_second_path_fails(self):
        x=a.symbolic_registration(0x00,0x03,caller="B")
        self.assertFalse(x["registrar_called_on_these_local_predicates"])
        self.assertIsNone(x["signed_adapter"])

    def test_signed_clearer_zeroes_both_callback_and_context(self):
        self.assertEqual(a.CLEAR_PINS[0x600D1122],
                         ("strd","r2, r2, [r3, #0xc]"))
        self.assertEqual(a.CLEAR_PINS[0x600D1120],("movs","r2, #0"))
        self.assertEqual(a.CLEAR_PINS[0x600D1126],
                         ("strb","r2, [r3, #0x14]"))
        self.assertEqual(a.endpoint_index(0x00),0)
        self.assertEqual(a.endpoint_index(0x80),1)

    def test_original_code_mutation_detected(self):
        self.assertEqual(a.validate_pins(dict(a.PINS)),len(a.PINS))
        changed=dict(a.PINS)
        changed[0x60054794]=("str.w","r7, [sp, #0xc]")
        with self.assertRaisesRegex(ValueError,"drift"):
            a.validate_pins(changed)

    def test_untrusted_image_and_bad_endpoints_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"not the real update")
        for invalid in (-1,256):
            with self.assertRaises(ValueError):
                a.select_a(invalid,1)
        with self.assertRaises(ValueError):
            a.symbolic_registration(0,0,caller="unknown")

if __name__=="__main__":
    unittest.main()
