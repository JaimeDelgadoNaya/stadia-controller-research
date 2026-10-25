"""Offline, synthetic-only image provenance regression tests."""
import unittest
from tools import audit_signed_bruce_variants as variants


class SignedBruceVariantTests(unittest.TestCase):
    def test_git_blob_id_uses_length_prefixed_git_object(self):
        self.assertEqual(variants.git_blob_id(b"test"),"30d74d258442c7c65512eafab474568dd706c430")

    def test_labels_are_pinned_and_strict(self):
        self.assertEqual(set(variants.EXPECTED_GIT_BLOBS),{"prod","stage","dev"})
        with self.assertRaisesRegex(ValueError,"Unknown provenance label"):
            variants.verify_variant("surprise",bytes(variants.SIZE))

    def test_reject_synthetic_image(self):
        for label in variants.EXPECTED_GIT_BLOBS:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError,"identity"):
                    variants.verify_variant(label,bytes(variants.SIZE))

    def test_signed_block_constant_cannot_be_conflated_with_cert_tail(self):
        self.assertEqual(variants.SIGN_LEN,variants.CSF)
        self.assertEqual(variants.SIZE-variants.SIGN_LEN,6456)
        self.assertEqual(variants.IVT,0xFF000)

    def test_full_comparison_requires_actual_archived_samples(self):
        with self.assertRaisesRegex(ValueError,"identity"):
            variants.compare_images(bytes(variants.SIZE),bytes(variants.SIZE),
                                    bytes(variants.SIZE))


if __name__=="__main__":
    unittest.main()
