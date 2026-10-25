"""Offline tests for bounded Bruce normal USB class receiver reconnaissance."""
import unittest
from tools import audit_bruce_class_requests as m

class BruceClassRequestTests(unittest.TestCase):
    def test_original_requires_exact_sha(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.inspect(bytes(m.IMAGE_SIZE))

    def test_literal_reference_sites_are_known(self):
        self.assertEqual(m.VENDOR_REFS,(0x21504,0x215B4))
        self.assertEqual(m.VENDOR_STRING_OFFSET,0xDE054)

    def test_comparison_is_only_candidate_not_proven_handler(self):
        self.assertEqual(m.classify_request_compare("cmp","r2, #0x81"),0x81)
        self.assertEqual(m.classify_request_compare("cmp","r1, #0x83"),0x83)
        self.assertEqual(m.classify_request_compare("cmp.w","r1, #0x84"),0x84)
        self.assertIsNone(m.classify_request_compare("cmp","r0, #5"))
        self.assertIsNone(m.classify_request_compare("mov","r0, #0x81"))
        self.assertIsNone(m.classify_request_compare("cmp","r0, r3"))
        self.assertIsNone(m.classify_request_compare("cmp","r0, #bad"))

    def test_disassembly_bounds(self):
        with self.assertRaises(ValueError):
            m.disassemble(b"test",-1,2)
        with self.assertRaises(ValueError):
            m.disassemble(b"test",2,2)
        with self.assertRaises(ValueError):
            m.disassemble(b"test",0,20)

if __name__=="__main__":
    unittest.main()
