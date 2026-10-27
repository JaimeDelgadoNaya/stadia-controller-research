"""Synthetic-only CSF UNLOCK byte layout; no firmware or hardware."""
import unittest
import struct

from tools.audit_hab_unlock_phase82 import decode_unlock_record, audit_unlock


def unlock(engine, features, uid=b""):
    payload = struct.pack(">I", features) + uid
    length = 4 + len(payload)
    return bytes((0xb2,)) + length.to_bytes(2, "big") + bytes((engine,)) + payload


class HABUnlockPhase82Tests(unittest.TestCase):
    def test_caam_feature_mask(self):
        result = decode_unlock_record(unlock(0x1d, 0x03))
        self.assertEqual(result["engine"], "CAAM")
        self.assertEqual(result["features"], ["MID", "RNG"])
        self.assertEqual(result["unmapped_features_mask"], "0x00000000")
        self.assertFalse(result["has_uid_field"])

    def test_ocotp_feature_mask_is_not_claimed_hab_bypass(self):
        result = decode_unlock_record(unlock(0x21, 0x0a))
        self.assertEqual(result["engine"], "OCOTP")
        self.assertEqual(result["features"], ["SRK_REVOKE", "JTAG"])
        self.assertIn("not removal of HAB", result["interpretation_limit"])

    def test_unknown_flags_are_not_named(self):
        result = decode_unlock_record(unlock(0x1d, 0x80000001))
        self.assertEqual(result["features"], ["MID"])
        self.assertEqual(result["unmapped_features_mask"], "0x80000000")

    def test_unknown_engine_is_explicit(self):
        result = decode_unlock_record(unlock(0xfe, 0x01))
        self.assertEqual(result["engine"], "UNKNOWN_ENGINE")
        self.assertEqual(result["features"], [])
        self.assertEqual(result["unmapped_features_mask"], "0x00000001")

    def test_uid_is_never_published(self):
        uid = bytes.fromhex("0102030405060708")
        result = decode_unlock_record(unlock(0x21, 0x01, uid))
        self.assertTrue(result["has_uid_field"])
        self.assertNotIn(uid.hex(), str(result))
        self.assertNotIn("0102030405060708", str(result))

    def test_empty_feature_mask(self):
        result = decode_unlock_record(unlock(0x0c, 0))
        self.assertEqual(result["features"], [])
        self.assertEqual(result["feature_mask"], "0x00000000")

    def test_malformed_lengths_fail_closed(self):
        examples = [
            b"", b"\xb2\x00\x07\x1d\x00\x00\x00",
            b"\xb2\x00\x09\x1d\x00\x00\x00\x01\xff",
            b"\xb2\x00\x08\x1d\x00\x00\x00",
            b"\xb2\x00\x08\x1d\x00\x00\x00\x00\xff",
            b"\xca\x00\x08\x1d\x00\x00\x00\x00",
        ]
        for value in examples:
            with self.subTest(value=value.hex()):
                with self.assertRaises(ValueError):
                    decode_unlock_record(value)

    def test_original_image_identity_enforced(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit_unlock(bytes(100672), "restricted_ram_loader")


if __name__ == "__main__":
    unittest.main()
