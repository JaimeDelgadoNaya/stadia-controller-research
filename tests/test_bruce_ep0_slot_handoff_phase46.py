"""Phase46 signed USB endpoint slot mapping, class event wrappers; no device."""
import unittest
from tools import audit_bruce_ep0_slot_handoff_phase46 as p

class EP0SlotHandoff46Tests(unittest.TestCase):
    def test_signed_endpoint_slot_mapping(self):
        self.assertEqual(p.endpoint_index(0x00),0)
        self.assertEqual(p.endpoint_index(0x80),1)
        self.assertEqual(p.endpoint_index(0x01),2)
        self.assertEqual(p.endpoint_index(0x81),3)
        self.assertEqual(p.endpoint_index(0x07),14)
        self.assertEqual(p.endpoint_index(0x87),15)
        with self.assertRaisesRegex(ValueError,"rejects"):
            p.endpoint_index(0x88)
        with self.assertRaisesRegex(ValueError,"0..255"):
            p.endpoint_index(256)

    def test_four_signed_class_adapters_do_not_pass_r1_brequest(self):
        self.assertEqual(sorted(x[3] for x in p.WRAPPERS.values()),[1,2,3,4])
        self.assertEqual(p.WRAPPERS["type4"],(0x600CFC1A,0x600CFC28,0x600CFC2A,4))
        self.assertEqual(p.WRAPPER_PINS[0x600CFC28],("movs","r1, #4"))
        self.assertEqual(p.WRAPPER_PINS[0x600CFC48],("bx","r3"))

    def test_mutation_rejected_even_with_valid_shape(self):
        pins={**p.PINS,**p.WRAPPER_PINS}
        self.assertEqual(p.verify_anchor_subset(pins,pins),len(pins))
        mutated=dict(pins)
        mutated[0x600D104E]=("bx","r5")
        with self.assertRaisesRegex(ValueError,"drift"):
            p.verify_anchor_subset(mutated,pins)

    def test_relocated_itcm_bounds_enforced(self):
        with self.assertRaisesRegex(ValueError,"out-of-range"):
            p.relocated_itcm_window(b"",0xC000,0xC010)

    def test_pinned_original_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"bad signed update")

if __name__=="__main__":
    unittest.main()
