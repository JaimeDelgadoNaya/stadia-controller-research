"""Synthetic-only IVT/CSF parser tests; no hardware or firmware blobs."""
import unittest
from tools.audit_nxp_rom_advisories_phase81 import parse_csf, audit


def command(tag, par=0, tail=b""):
    return bytes([tag]) + (4 + len(tail)).to_bytes(2, "big") + bytes([par]) + tail


def csf(*commands):
    body = b"".join(commands)
    return b"\xd4" + (4 + len(body)).to_bytes(2, "big") + b"\x42" + body


class NxpAdvisoryTests(unittest.TestCase):
    def test_supported_normal_original_command_classes(self):
        blob = csf(command(0xbe, tail=b"12345678"),
                   command(0xca, tail=b"12345678"))
        size, commands = parse_csf(blob, 0)
        self.assertEqual(size, len(blob))
        self.assertEqual([x["name"] for x in commands],
                         ["INSTALL_KEY", "AUTHENTICATE_DATA"])
        self.assertFalse(any(x["deprecated"] for x in commands))

    def test_deprecated_commands_are_flagged(self):
        _, commands = parse_csf(csf(command(0xcc), command(0xcf),
                                    command(0xb1, 0x01)), 0)
        self.assertEqual([x["deprecated"] for x in commands],
                         ["WRITE_DATA", "CHECK_DATA", "SET_MID"])

    def test_non_mid_set_is_not_a_false_positive(self):
        _, commands = parse_csf(csf(command(0xb1, 0x02)), 0)
        self.assertIsNone(commands[0]["deprecated"])

    def test_unknown_command_is_exposed(self):
        _, commands = parse_csf(csf(command(0xed)), 0)
        self.assertEqual(commands[0]["name"], "UNKNOWN")

    def test_truncated_and_invalid_csf_rejected(self):
        cases = [b"", b"\xd4\x00\x03\x42",
                 b"\xd4\x00\x08\x42\xbe\x00\x02\x00",
                 b"\xd4\x00\x09\x42\xbe\x00\x06\x00\x00",
                 b"\xd4\x00\x08\x42\xbe\x00"]
        for blob in cases:
            with self.subTest(blob=blob.hex()):
                with self.assertRaises(ValueError):
                    parse_csf(blob, 0)

    def test_parse_csf_only_at_declared_offset(self):
        size, commands = parse_csf(b"\xff" * 64 + csf(command(0xca)), 64)
        self.assertEqual(size, 8)
        self.assertEqual(commands[0]["relative_offset"], "0x4")

    def test_wrong_original_hash_fails_before_any_claim(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(bytes(1050984), "bruce_prod")

    def test_unknown_sample_fails(self):
        with self.assertRaisesRegex(ValueError, "Unknown"):
            audit(b"", "not_a_sample")


if __name__ == "__main__":
    unittest.main()
