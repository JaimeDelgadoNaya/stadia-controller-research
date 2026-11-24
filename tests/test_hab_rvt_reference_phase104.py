"""Phase 104: synthetic tests of the public HAB RVT evidence parser."""
import struct
import unittest

from research.phase104.audit_hab_rvt_reference import (
    public_rom_audit, EXPECTED_SHA, ROM_BYTES, RVT_OFFSET
)
from tools.audit_hab_rom_version_phase83 import parse_rvt_snapshot


def make_snapshot(pointer=0x002147F9, auth=0x00210001):
    d = bytearray(0x34)
    d[:4] = bytes([0xdd,0,0x34,0x40])
    struct.pack_into("<I",d,0x2c,auth)
    struct.pack_into("<I",d,0x30,pointer)
    return bytes(d)


class HABReferencePhase104Tests(unittest.TestCase):
    def test_01_public_rom_is_hash_gated(self):
        self.assertEqual(len(EXPECTED_SHA), 64)

    def test_02_reject_bad_rom_size(self):
        with self.assertRaisesRegex(ValueError,"128 KiB"):
            public_rom_audit(b"")

    def test_03_reject_wrong_public_reference_hash(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            public_rom_audit(bytes(ROM_BYTES))

    def test_04_synthetic_rvt_parse(self):
        d=parse_rvt_snapshot(make_snapshot())
        self.assertEqual(d["declared_bytes"],0x34)
        self.assertEqual(d["rvt_header_version_byte"],"0x40")

    def test_05_thumb_pointer_validated_as_data(self):
        d=parse_rvt_snapshot(make_snapshot())
        self.assertEqual(d["get_version_slot"]["pointer"],"0x002147f9")
        self.assertTrue(d["get_version_slot"]["points_into_documented_rom_region"])
        self.assertFalse(d["get_version_slot"]["function_invoked"])

    def test_06_even_pointer_not_thumb(self):
        d=parse_rvt_snapshot(make_snapshot(pointer=0x002147F8))
        self.assertFalse(d["get_version_slot"]["points_into_documented_rom_region"])

    def test_07_outside_rom_pointer_rejected(self):
        d=parse_rvt_snapshot(make_snapshot(pointer=0x60800001))
        self.assertFalse(d["get_version_slot"]["points_into_documented_rom_region"])

    def test_08_header_version_not_patch_level(self):
        d=parse_rvt_snapshot(make_snapshot())
        self.assertEqual(d["rvt_header_patch_version"],"NOT_ENCODED_IN_HEADER")
        self.assertEqual(d["get_version_slot"]["library_patch_version"],"UNKNOWN_UNTIL_GET_VERSION_RESULT")

    def test_09_bad_rvt_tag_rejected(self):
        x=bytearray(make_snapshot());x[0]=0xd1
        with self.assertRaisesRegex(ValueError,"tag"):
            parse_rvt_snapshot(bytes(x))

    def test_10_truncated_rvt_rejected(self):
        with self.assertRaisesRegex(ValueError,"truncated"):
            parse_rvt_snapshot(make_snapshot()[:28])

    def test_11_rvt_location_reference_only(self):
        self.assertEqual(RVT_OFFSET,0x300)

if __name__ == "__main__":
    unittest.main(verbosity=2)
