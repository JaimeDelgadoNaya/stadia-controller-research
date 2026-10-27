"""Phase83 synthetic-only checks: source evidence != ROM HAB patch version."""
import struct
import unittest

from tools.audit_hab_rom_version_phase83 import (
    HAB_AUTH_NO_DCD_SLOT_OFFSET, HAB_GET_VERSION_SLOT_OFFSET,
    RVT_BASE, audit, parse_rvt_snapshot,
)


def fake_rvt(header_version=0x43, length=0x34, auth_ptr=0x00206101,
             version_ptr=0x00206781):
    raw = bytearray(max(length, 4))
    raw[0] = 0xdd
    raw[1:3] = length.to_bytes(2, "big")
    raw[3] = header_version
    if length >= 0x30:
        struct.pack_into("<I", raw, HAB_AUTH_NO_DCD_SLOT_OFFSET, auth_ptr)
    if length >= 0x34:
        struct.pack_into("<I", raw, HAB_GET_VERSION_SLOT_OFFSET, version_ptr)
    return bytes(raw)


class ROMHABVersionPhase83Tests(unittest.TestCase):
    def test_synthetic_rvt_pointer_slots_are_not_code_entry_addresses(self):
        result = parse_rvt_snapshot(fake_rvt())
        self.assertEqual(result["slot_get_version_address"], "0x00200330")
        self.assertEqual(result["slot_authenticate_image_no_dcd_address"], "0x0020032c")
        self.assertEqual(result["get_version_slot"]["pointer"], "0x00206781")
        self.assertTrue(result["get_version_slot"]["points_into_documented_rom_region"])
        self.assertFalse(result["get_version_slot"]["function_invoked"])

    def test_header_minor_nibble_does_not_prove_patch(self):
        result = parse_rvt_snapshot(fake_rvt(header_version=0x43))
        self.assertEqual(result["rvt_header_version_byte"], "0x43")
        self.assertEqual(result["rvt_header_patch_version"], "NOT_ENCODED_IN_HEADER")
        self.assertEqual(result["get_version_slot"]["library_patch_version"],
                         "UNKNOWN_UNTIL_GET_VERSION_RESULT")

    def test_no_get_version_pointer_for_short_rvt(self):
        result = parse_rvt_snapshot(fake_rvt(header_version=0x42, length=0x30))
        self.assertEqual(result["get_version_slot"], "NOT_PRESENT_IN_DECLARED_RVT")
        self.assertTrue(result["authenticate_image_no_dcd_slot"][
            "points_into_documented_rom_region"])

    def test_bad_rvt_tag_and_header_major_fail(self):
        for blob in (b"", b"\x00\x00\x34\x43" + bytes(48),
                     fake_rvt(header_version=0x53),
                     b"\xdd\x00\x03\x42",
                     b"\xdd\x00\x34\x42"):
            with self.subTest(blob=blob[:4].hex()):
                with self.assertRaises(ValueError):
                    parse_rvt_snapshot(blob)

    def test_bad_pointer_is_marked_unverified(self):
        result = parse_rvt_snapshot(fake_rvt(version_ptr=0x60040001))
        self.assertFalse(result["get_version_slot"]["points_into_documented_rom_region"])
        result = parse_rvt_snapshot(fake_rvt(version_ptr=0))
        self.assertFalse(result["get_version_slot"]["points_into_documented_rom_region"])

    def test_rvt_len_must_be_word_aligned(self):
        raw = b"\xdd\x00\x35\x43" + bytes(0x31)
        with self.assertRaisesRegex(ValueError, "aligned"):
            parse_rvt_snapshot(raw)

    def test_owner_rom_version_not_inferred_from_wrong_firmware(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(bytes(1050984), "bruce_prod")

    def test_get_version_value_requires_rom_snapshot(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(bytes(100672), "restricted_ram_loader", get_version_return=0x040306)

    def test_oversized_snapshot_rejected(self):
        with self.assertRaisesRegex(ValueError, "snapshot size"):
            parse_rvt_snapshot(fake_rvt() + bytes(300))

    def test_documented_absolute_slot_addresses(self):
        self.assertEqual(RVT_BASE + HAB_GET_VERSION_SLOT_OFFSET, 0x00200330)
        self.assertEqual(RVT_BASE + HAB_AUTH_NO_DCD_SLOT_OFFSET, 0x0020032c)


if __name__ == "__main__":
    unittest.main()
