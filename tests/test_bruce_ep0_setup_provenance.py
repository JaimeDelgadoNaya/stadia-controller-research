"""Pure synthetic regression tests for Bruce EP0 SETUP provenance classifier."""
import unittest
from tools import audit_bruce_ep0_setup_provenance as m


class Ep0SetupProvenanceTests(unittest.TestCase):
    def test_host_setup_layout_not_confused_with_payload(self):
        self.assertEqual(m.USB_SETUP_FIELDS["bmRequestType"],0)
        self.assertEqual(m.USB_SETUP_FIELDS["bRequest"],1)
        self.assertEqual(m.USB_SETUP_FIELDS["wLength"],(6,7))

    def test_simple_byte_loads_and_offsets(self):
        self.assertEqual(m.parse_byte_load("ldrb","r3, [r1]"),("r3","r1",0))
        self.assertEqual(m.parse_byte_load("ldrb.w","r3, [r7, #0x53]"),("r3","r7",0x53))
        self.assertEqual(m.parse_byte_load("ldrb","r3, [r1, #1]"),("r3","r1",1))
        self.assertIsNone(m.parse_byte_load("ldr","r3, [r1, #1]"))
        self.assertIsNone(m.parse_byte_load("ldrb.w","r0, [sp, r5]"))

    def test_immediate_comparisons(self):
        self.assertEqual(m.parse_immediate_compare("cmp","r3, #0x81"),("r3",0x81))
        self.assertEqual(m.parse_immediate_compare("cmp.w","r12, #131"),("r12",131))
        self.assertIsNone(m.parse_immediate_compare("cmn","r3, #0x81"))
        self.assertIsNone(m.parse_immediate_compare("cmp","r3, r5"))

    def test_buffer_zero_not_setup_brequest(self):
        rows=[{"pc":0x100,"m":"ldrb","op":"r3, [r1]"},
              {"pc":0x102,"m":"cmp","op":"r3, #0x81"}]
        result=m.immediate_provenance(rows,0x102,0x81)
        self.assertTrue(result["direct_ldrb_at_payload_first_byte_offset_0"])
        self.assertFalse(result["direct_ldrb_at_setup_brequest_offset_1"])
        self.assertFalse(result["usb_setup_object_provenance_verified"])

    def test_setup_offset_one_is_only_candidate_not_proven(self):
        rows=[{"pc":0x100,"m":"ldrb","op":"r3, [r1, #1]"},
              {"pc":0x102,"m":"cmp","op":"r3, #0x84"}]
        result=m.immediate_provenance(rows,0x102,0x84)
        self.assertTrue(result["direct_ldrb_at_setup_brequest_offset_1"])
        self.assertFalse(result["usb_setup_object_provenance_verified"])
        self.assertFalse(result["executable_and_reachable_from_ep0_verified"])

    def test_missing_or_drifted_candidate_rejected(self):
        with self.assertRaisesRegex(ValueError,"missing"):
            m.immediate_provenance([],0x102,0x84)
        with self.assertRaisesRegex(ValueError,"changed"):
            m.immediate_provenance([{"pc":0x102,"m":"cmp","op":"r3, #0x80"}],0x102,0x84)

    def test_image_requires_real_hash(self):
        with self.assertRaisesRegex(ValueError,"Exact SHA"):
            m.audit(bytes(m.IMAGE_SIZE))


if __name__=="__main__":
    unittest.main()
