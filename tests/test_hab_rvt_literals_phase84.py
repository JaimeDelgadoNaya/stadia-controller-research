"""Synthetic offline tests for phase84 raw HAB RVT literal census."""
import struct
import unittest

from tools.audit_hab_rvt_literals_phase84 import (
    MAX_HITS, RVT_BASE, SLOTS, audit, census_pre_csf_words, thumb_pc_relative_ldr_candidates,
)


class RVTLiteralPhase84Tests(unittest.TestCase):
    def test_known_slots_are_detected(self):
        sample = bytearray(b"\xff" * 128)
        for at, delta in ((8, 0x00), (20, 0x2C), (32, 0x30), (44, 0x24)):
            struct.pack_into("<I", sample, at, RVT_BASE + delta)
        result = census_pre_csf_words(bytes(sample), len(sample))
        self.assertEqual([x["file_offset"] for x in result],
                         ["0x8", "0x14", "0x20", "0x2c"])
        self.assertEqual([x["slot_name"] for x in result],
                         ["rvt_base", "authenticate_image_no_dcd_slot",
                          "get_version_slot", "report_status_slot"])

    def test_halfword_misalignment_is_labeled_not_proven_code(self):
        raw = bytearray(b"\xff" * 16)
        struct.pack_into("<I", raw, 2, RVT_BASE + 0x30)
        hits = census_pre_csf_words(bytes(raw), len(raw))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["word_alignment"], "2_byte_only")
        self.assertFalse(hits[0]["instruction_reference_confirmed"])

    def test_byte_misaligned_literal_does_not_match(self):
        raw = bytearray(b"\xff" * 16)
        struct.pack_into("<I", raw, 3, RVT_BASE + 0x30)
        self.assertEqual(census_pre_csf_words(bytes(raw), len(raw)), [])

    def test_pre_csf_limit_prevents_scanning_trailer(self):
        raw = bytearray(b"\xff" * 32)
        struct.pack_into("<I", raw, 28, RVT_BASE + 0x30)
        self.assertEqual(census_pre_csf_words(bytes(raw), 28), [])
        self.assertEqual(len(census_pre_csf_words(bytes(raw), 32)), 1)

    def test_same_slot_can_appear_in_data_not_executable_code(self):
        raw = bytearray(b"\xff" * 64)
        struct.pack_into("<I", raw, 4, RVT_BASE + 0x30)
        struct.pack_into("<I", raw, 40, RVT_BASE + 0x30)
        hits = census_pre_csf_words(bytes(raw), 64)
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(h["instruction_reference_confirmed"] is False
                            for h in hits))

    def test_no_candidates_does_not_establish_absence_of_indirect_call(self):
        self.assertEqual(census_pre_csf_words(b"\xff" * 64, 64), [])
        self.assertIn("get_version_slot", SLOTS.values())

    def test_reject_invalid_bounds_and_types(self):
        for data, limit in ((bytes(10), 11), (bytes(10), -1),
                            (b"", 2), (bytearray(10), 10)):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    census_pre_csf_words(data, limit)

    def test_overabundant_hits_fail_closed(self):
        raw = struct.pack("<I", RVT_BASE) * (MAX_HITS + 2)
        with self.assertRaisesRegex(ValueError, "Too many"):
            census_pre_csf_words(raw, len(raw))

    def test_wrong_hash_rejected_before_finding_candidates(self):
        image = bytearray(100672)
        struct.pack_into("<I", image, 200, RVT_BASE + 0x30)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(bytes(image), "restricted_ram_loader")

    def test_slot_addresses_are_expected(self):
        self.assertEqual(SLOTS[RVT_BASE + 0x2C],
                         "authenticate_image_no_dcd_slot")
        self.assertEqual(SLOTS[RVT_BASE + 0x30], "get_version_slot")


    def test_thumb16_literal_load_encoding_is_only_syntactic_candidate(self):
        raw = bytearray(b"\\xff" * 32)
        struct.pack_into("<H", raw, 0, 0x4801)  # pc 4 + imm8*4 = file offset 8
        struct.pack_into("<I", raw, 8, RVT_BASE + 0x30)
        hits = census_pre_csf_words(bytes(raw), len(raw))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["slot_name"], "get_version_slot")
        self.assertEqual(hits[0]["syntactic_thumb_load_candidates"][0][
            "encoding_shape"], "thumb16_ldr_literal_t1")
        self.assertFalse(hits[0]["syntactic_thumb_load_candidates"][0][
            "instruction_boundary_verified"])

    def test_thumb32_literal_load_encoding_is_only_syntactic_candidate(self):
        raw = bytearray(b"\\xff" * 32)
        struct.pack_into("<HH", raw, 0, 0xf8df, 0x0004)  # pc 4 + imm12 4 = 8
        struct.pack_into("<I", raw, 8, RVT_BASE + 0x2c)
        candidates = thumb_pc_relative_ldr_candidates(bytes(raw), 8)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["encoding_shape"], "thumb32_ldr_literal_t2")
        self.assertFalse(candidates[0]["executed_or_reachable"])

    def test_literal_with_no_encoded_load_is_not_proven_unreferenced(self):
        raw = bytearray(b"\\xff" * 32)
        struct.pack_into("<I", raw, 8, RVT_BASE)
        hits = census_pre_csf_words(bytes(raw), len(raw))
        self.assertEqual(hits[0]["syntactic_thumb_load_candidates"], [])
        self.assertFalse(hits[0]["instruction_reference_confirmed"])


if __name__ == "__main__":
    unittest.main()
