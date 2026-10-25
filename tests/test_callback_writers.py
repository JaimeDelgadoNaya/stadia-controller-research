"""Phase 20 — synthetic tests of bounded callback mutation encoding searches."""
import hashlib
import struct
import unittest

from tools import audit_callback_writers as m


def fixture():
    blob = bytearray(b"\xff" * m.SIZE)
    for offset, hex_bytes in m.INITIALIZERS.items():
        raw = bytes.fromhex(hex_bytes)
        blob[offset:offset+len(raw)] = raw
    return bytes(blob)


def audited(blob):
    return m.audit(blob, expected_sha256=hashlib.sha256(blob).hexdigest())


class CallbackWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic = fixture()

    def test_default_sha_rejects_fake_image(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.audit(self.synthetic)

    def test_only_initializers_in_synthetic_image(self):
        report = audited(self.synthetic)
        self.assertTrue(report["sha256_verified"])
        self.assertFalse(report["device_access"])
        for name, info in report["fields"].items():
            self.assertEqual(len(info["positive_immediate_strw_candidates"]), 1, name)
            self.assertEqual(info["other_than_initializer"], [])
            self.assertEqual(info["aligned_absolute_pointer_literals"], [])
        self.assertEqual(report["later_replacement"], "NOT PROVEN AND NOT EXCLUDED")

    def test_actual_initializer_addresses_are_preserved(self):
        r = audited(self.synthetic)
        self.assertEqual(r["fields"]["bulk_in_handler"]["initializer"], "0x6080bb50")
        self.assertEqual(r["fields"]["bulk_out_handler"]["initializer"], "0x6080bb5a")
        self.assertEqual(r["fields"]["bulk_in_context"]["initializer"], "0x6080bb6c")
        self.assertEqual(r["fields"]["bulk_out_context"]["initializer"], "0x6080bb70")

    def test_extra_strw_with_different_base_source_found(self):
        blob = bytearray(self.synthetic)
        # STR.W R7,[R1,#0x600] at a candidate halfword boundary.
        struct.pack_into("<HH", blob, 0x1100, 0xF8C1, 0x7600)
        extra = audited(bytes(blob))["fields"]["bulk_out_handler"]["other_than_initializer"]
        self.assertEqual(len(extra), 1)
        self.assertEqual(extra[0]["address"], "0x60801100")
        self.assertEqual(extra[0]["base_register"], "r1")
        self.assertEqual(extra[0]["source_register"], "r7")

    def test_thumb2_raw_scan_does_not_promote_candidate_to_reachability(self):
        blob = bytearray(self.synthetic)
        struct.pack_into("<HH", blob, 0x1100, 0xF8C1, 0x7600)
        report = audited(bytes(blob))
        self.assertIn("candidate", report["fields"]["bulk_out_handler"][
            "other_than_initializer"][0]["status"])
        self.assertEqual(report["host_to_flash_write"], "NOT DEMONSTRATED")

    def test_odd_halfword_offset_is_not_an_instruction_boundary(self):
        blob = bytearray(self.synthetic)
        struct.pack_into("<HH", blob, 0x1101, 0xF8C1, 0x7600)
        result = audited(bytes(blob))
        self.assertEqual(result["fields"]["bulk_out_handler"]["other_than_initializer"], [])

    def test_thumb16_word_store_with_object_relative_offset(self):
        blob = bytearray(self.synthetic)
        # STR R3,[R2,#0x18], Thumb16 encoding.
        struct.pack_into("<H", blob, 0xA020, 0x6193)
        cases = audited(bytes(blob))["vendor_object_local_store_candidates"]["0x18"][
            "thumb16_word_store_candidates"]
        self.assertTrue(any(c["address"] == "0x6080a020" and
                            c["base_register"] == "r2" for c in cases))

    def test_thumb2_word_store_with_object_relative_offset(self):
        blob = bytearray(self.synthetic)
        struct.pack_into("<HH", blob, 0xA020, 0xF8C0, 0x3018)
        cases = audited(bytes(blob))["vendor_object_local_store_candidates"]["0x18"][
            "thumb2_positive_strw_candidates"]
        self.assertTrue(any(c["address"] == "0x6080a020" and
                            c["base_register"] == "r0" for c in cases))

    def test_absolute_pointer_literal_found_only_when_present(self):
        blob = bytearray(self.synthetic)
        struct.pack_into("<I", blob, 0x1200, m.CALLBACK_FIELDS["bulk_out_handler"][0])
        result = audited(bytes(blob))
        self.assertEqual(result["fields"]["bulk_out_handler"][
            "aligned_absolute_pointer_literals"], ["0x60801200"])

    def test_non_aligned_absolute_pointer_does_not_count(self):
        blob = bytearray(self.synthetic)
        struct.pack_into("<I", blob, 0x1201, m.CALLBACK_FIELDS["bulk_out_handler"][0])
        result = audited(bytes(blob))
        self.assertEqual(result["fields"]["bulk_out_handler"][
            "aligned_absolute_pointer_literals"], [])

    def test_constructor_mutation_rejected(self):
        blob = bytearray(self.synthetic)
        blob[0xBB5A] ^= 1
        with self.assertRaisesRegex(ValueError, "anchor"):
            audited(bytes(blob))

    def test_stub_mutation_rejected(self):
        blob = bytearray(self.synthetic)
        blob[0xAFFC] ^= 1
        with self.assertRaisesRegex(ValueError, "anchor"):
            audited(bytes(blob))

    def test_wrong_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            audited(self.synthetic[:-1])

    def test_invalid_immediate_rejected(self):
        for immediate in (-1, 0x1000, "0x600"):
            with self.subTest(immediate=immediate), self.assertRaises(ValueError):
                m.scan_thumb2_positive_str(self.synthetic, immediate)

    def test_misaligned_or_invalid_scan_bounds_rejected(self):
        for start, end in ((0x1001, 0x1200), (0x1100, 0x1101),
                           (0x1300, 0x1100), (-2, 0x1000)):
            with self.subTest(bounds=(start,end)), self.assertRaises(ValueError):
                m.scan_thumb2_positive_str(self.synthetic, 0x600, start, end)

    def test_thumb16_invalid_immediate_rejected(self):
        for value in (-4, 0x7d, 0x80):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.scan_thumb16_str_word(self.synthetic, value)

    def test_final_status_preserves_uncertainty(self):
        report = audited(self.synthetic)
        self.assertEqual(report["host_bulk_out_to_message_parser"], "NOT ESTABLISHED")
        self.assertEqual(report["hab_closed_bypass"], "NOT DEMONSTRATED")
        self.assertEqual(report["custom_firmware_execution"], "NOT DEMONSTRATED")
        self.assertIn("NOT ANALYZED", report["other_store_forms_or_pointer_aliases"])


if __name__ == "__main__":
    unittest.main()
