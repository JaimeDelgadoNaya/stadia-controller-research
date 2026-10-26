"""No hardware involved. Synthetic regression checks for signed USB SETUP provenance."""
import struct
import unittest
from tools import audit_bruce_setup_verified as a

class SignedSetupSemanticTests(unittest.TestCase):
    def test_requires_exact_original_signed_sample(self):
        with self.assertRaisesRegex(ValueError,"Exact original"):
            a.audit(bytes(a.IMAGE_SIZE))

    def test_anchor_manifest_required(self):
        self.assertTrue(a.check_anchors(dict(a.ANCHORS)))
        edited=dict(a.ANCHORS)
        edited[0x600D0EB8]=("ldrb","r1, [r1, #4]")
        with self.assertRaisesRegex(ValueError,"semantic drift"):
            a.check_anchors(edited)

    def test_class_request_distinct_from_descriptor_byte(self):
        self.assertEqual(a.ANCHORS[0x600D0EB8],("ldrb","r1, [r1, #1]"))
        self.assertEqual(a.ANCHORS[0x600CFCD4],("ldr","r2, [r3, #8]"))
        self.assertEqual(a.ANCHORS[0x600CFCDC],("and","r3, r3, #0x30"))
        self.assertEqual(a.ANCHORS[0x600D0EBA],("ldr","r3, [r3]"))

    def test_literal_table_is_data(self):
        blob=bytearray(0xC0000)
        struct.pack_into("<I",blob,0xC4BAC,0x600D0E59)
        rows=a.literal_table(blob)
        self.assertEqual([x["word"] for x in rows if x["pc"]=="0x60104bac"],
                         ["0x600d0e59"])
        with self.assertRaises(ValueError):
            a.literal_table(blob,0x60104B89,0x60104BD0)

    def test_accepted_standard_brequest_bounds_only(self):
        self.assertIn((0x600D0D54,("cmp","r2, #0xa")),a.ANCHORS.items())
        self.assertEqual(a.ANCHORS[0x600D0D52],("subs","r2, #1"))
        self.assertNotIn(0x81,range(1,12))
        self.assertNotIn(0x83,range(1,12))
        self.assertNotIn(0x84,range(1,12))

if __name__=="__main__":
    unittest.main()
