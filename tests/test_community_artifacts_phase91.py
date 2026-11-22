"""Fail-closed offline tests using entirely synthetic bytes."""
import hashlib
import io
import json
import struct
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.audit_community_artifacts_phase91 import (
    MAX_BYTES, bootloader_summary, bonding_summary, _read_limited, main,
)


def fake_image(with_strings=False):
    data = bytearray(256)
    struct.pack_into("<8I", data, 0,
        0x412000d1, 0x60801000, 0, 0, 0x60001020, 0x60001000, 0, 0)
    if with_strings:
        data[40:40+len(b"usb_device_cdc_acm.c")] = b"usb_device_cdc_acm.c"
    return bytes(data)


class LocalArtifactPhase91Tests(unittest.TestCase):
    def test_ivt_fields_and_hash(self):
        blob = fake_image()
        result = bootloader_summary(blob)
        self.assertEqual(result["ivt_fields"]["self"], "0x60001000")
        self.assertEqual(result["sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(result["kind"], "ivt_candidate_not_authenticated")
        self.assertFalse(result["oem_signature_validated"])

    def test_cdc_string_not_descriptor_validation(self):
        result = bootloader_summary(fake_image(True))
        self.assertTrue(result["static_string_markers"]["cdc_acm_source_string"])
        self.assertFalse(result["cdc_descriptor_correctness_validated"])

    def test_unrecognized_ivt_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "No expected"):
            bootloader_summary(b"\xff" * 100)

    def test_too_short_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "at least"):
            bootloader_summary(b"\xd1\x00\x20\x41")

    def test_bonding_is_private_even_if_contains_secret(self):
        result = bonding_summary(b"#BONDING\x00private-device-id-and-key")
        serialized = json.dumps(result)
        self.assertEqual(result["kind"], "private_bonding_store_not_firmware")
        self.assertNotIn("private-device", serialized)
        self.assertNotIn('\"sha256\"', serialized)

    def test_unrecognized_bonding_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Not a recognized"):
            bonding_summary(b"NOT-A-STORE")

    def test_missing_and_oversized_file_rejected(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "missing"):
                _read_limited(Path(tmp) / "missing")
            p = Path(tmp) / "oversized.bin"
            with p.open("wb") as handle:
                handle.truncate(MAX_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                _read_limited(p)

    def test_cli_only_emits_sanitized_json(self):
        with TemporaryDirectory() as tmp:
            boot = Path(tmp) / "candidate.bin"
            private = Path(tmp) / "bonding.bin"
            boot.write_bytes(fake_image())
            private.write_bytes(b"#BONDING\x00SECRET_123")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(["--bootloader", str(boot), "--bonding", str(private)])
            report = json.loads(buffer.getvalue())
            self.assertFalse(report["device_actions"])
            self.assertNotIn("SECRET_123", buffer.getvalue())
            self.assertNotIn("sha256", report["bonding"])


if __name__ == "__main__":
    unittest.main()
