"""Synthetic tests; no firmware, hardware or network access."""
import unittest
import struct
from tools import audit_signed_app_host_boundary as audit


class SignedAppHostBoundaryTests(unittest.TestCase):
    def test_segment_classification_exact_boundaries(self):
        tests=[
          (0,"authenticated_application_content"),
          (audit.IVT-1,"authenticated_application_content"),
          (audit.IVT,"authenticated_ivt_prefix"),
          (audit.CSF-1,"authenticated_ivt_prefix"),
          (audit.CSF,"csf_commands_not_part_of_application_signed_block"),
          (audit.CSF_END-1,"csf_commands_not_part_of_application_signed_block"),
          (audit.CSF_END,"post_csf_signature_certificate_or_padding"),
          (audit.SIZE-1,"post_csf_signature_certificate_or_padding"),
        ]
        for x,expected in tests:
            with self.subTest(x=x):
                self.assertEqual(audit.classify_offset(x),expected)
        for x in (-1,audit.SIZE):
            with self.assertRaises(ValueError):
                audit.classify_offset(x)

    def test_tail_is_separate_from_signed_app(self):
        self.assertEqual(audit.IVT,0xFF000)
        self.assertEqual(audit.CSF,0xFF030)
        self.assertEqual(audit.CSF_END,0xFF078)
        self.assertEqual(audit.SIZE-audit.CSF,6456)

    def test_static_word_candidates_are_not_execution_proof(self):
        fake=bytearray(audit.SIZE)
        ptr=audit.BASE+audit.CSF_END
        struct.pack_into("<I",fake,0x100,ptr|1)
        struct.pack_into("<I",fake,0x104,ptr)
        struct.pack_into("<I",fake,0x108,audit.BASE+audit.IVT)
        struct.pack_into("<I",fake,audit.CSF+8,ptr)
        candidates=audit.static_tail_references(fake)
        self.assertEqual(len(candidates),2)
        self.assertEqual([x["word_offset"] for x in candidates],["0x100","0x104"])
        self.assertEqual(candidates[0]["target_kind"],
                         "post_csf_signature_certificate_or_padding")
        self.assertTrue(candidates[0]["thumb_bit"])
        self.assertFalse(candidates[1]["thumb_bit"])

    def test_reject_empty_or_different_image_even_with_injected_validators(self):
        with self.assertRaisesRegex(ValueError,"SHA-pinned"):
            audit.evaluate_boundaries(bytes(audit.SIZE),b"test",
                   verifier=lambda *_: None,
                   inspect_surface=lambda *_: None,
                   inspect_dispatch=lambda *_: None,
                   inspect_host=lambda *_: None)

    def test_reference_scan_excludes_unsigned_source_tail(self):
        fake=bytearray(audit.SIZE)
        struct.pack_into("<I",fake,audit.IVT-4,audit.BASE+audit.CSF)
        struct.pack_into("<I",fake,audit.CSF,audit.BASE+audit.CSF+4)
        candidates=audit.static_tail_references(fake)
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0]["word_offset"],hex(audit.IVT-4))

    def test_requires_whole_file_length(self):
        with self.assertRaisesRegex(ValueError,"wrong image"):
            audit.static_tail_references(bytes(20))


if __name__ == "__main__":
    unittest.main()
