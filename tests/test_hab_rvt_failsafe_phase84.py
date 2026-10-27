"""Synthetic phase84 checks for pinned HAB failsafe veneer interpretation."""
import struct
import unittest

from tools.audit_hab_rvt_failsafe_phase84 import (
    audit, decode_pinned_fragment, INSTRUCTION_OFFSET, LITERAL_OFFSET,
    EXPECTED_THUMB, RVT_BASE,
)


def fixture():
    data = bytearray(b"\xff" * (LITERAL_OFFSET + 64))
    data[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + len(EXPECTED_THUMB)] = EXPECTED_THUMB
    struct.pack_into("<I", data, LITERAL_OFFSET, RVT_BASE)
    return bytes(data)


class FailsafeVeneerPhase84Tests(unittest.TestCase):
    def test_exact_original_fragment_is_failsafe_not_get_version(self):
        result = decode_pinned_fragment(fixture())
        self.assertEqual(result["signed_literal_value"], "0x00200300")
        self.assertEqual(result["computed_literal_file_offset"], "0x810")
        self.assertEqual(result["rvt_indirect_pointer_slot"], "0x00200328")
        self.assertEqual(result["rvt_member_by_nxp_layout"], "failsafe")
        self.assertFalse(result["get_version_called_by_this_sequence"])
        self.assertEqual(result["reachable_from_physical_event"], "NOT_ESTABLISHED")

    def test_machine_code_matches_expected_thumb_words(self):
        self.assertEqual(struct.unpack("<HHH", EXPECTED_THUMB),
                         (0x483A, 0x6A81, 0x4708))

    def test_mutated_ldr_and_bx_rejected(self):
        for i in range(len(EXPECTED_THUMB)):
            image = bytearray(fixture())
            image[INSTRUCTION_OFFSET + i] ^= 0x01
            with self.subTest(byte=i):
                with self.assertRaises(ValueError):
                    decode_pinned_fragment(bytes(image))

    def test_non_rvt_literal_rejected(self):
        image = bytearray(fixture())
        struct.pack_into("<I", image, LITERAL_OFFSET, 0x00200330)
        with self.assertRaisesRegex(ValueError, "HAB RVT base"):
            decode_pinned_fragment(bytes(image))

    def test_truncated_image_rejected(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            decode_pinned_fragment(fixture()[:LITERAL_OFFSET + 1])

    def test_wrong_signed_image_hash_fails_before_result(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(fixture())


if __name__ == "__main__":
    unittest.main()
