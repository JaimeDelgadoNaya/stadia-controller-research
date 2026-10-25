"""Bounded offline tests for phase 13, with synthetic USB descriptors and Thumb."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

from tools.audit_usb_surface import (
    BASE, IMAGE_SIZE, KNOWN_SHA256, audit_public_evidence, audit_local_image,
)


def synthetic_image(descriptor=True, vector=True):
    data = bytearray(b"\xFF" * IMAGE_SIZE)
    if vector:
        struct.pack_into("<II", data, 0x1000, 0x20010000, BASE + 0x3001)
    # LDR R0, [PC, #0]; BX LR; .word descriptor_absolute_address
    data[0x3000:0x3004] = b"\x00\x48\x70\x47"
    struct.pack_into("<I", data, 0x3004, BASE + 0x5000)
    if descriptor:
        data[0x5000:0x5012] = bytes.fromhex(
            "12 01 00 02 00 00 00 40 d1 18 6b 94 00 01 01 02 03 01"
        )
    return bytes(data)


class UsbTriageTests(unittest.TestCase):
    def test_public_selection_is_not_full_dispatch(self):
        evidence = json.loads((Path(__file__).resolve().parents[1] /
                               "evidence/bootloader-analysis.json").read_text())
        report = audit_public_evidence(evidence)
        self.assertEqual(report["selected_regions"], 28)
        self.assertEqual(report["selected_instruction_bytes"], 2340)
        self.assertEqual(report["direct_calls"], 67)
        self.assertEqual(report["direct_calls_outside_selection"], 41)
        self.assertEqual(report["indirect_transfer_sites"], 16)
        self.assertEqual(report["usb_to_writer_reachability"], "NOT DEMONSTRATED")
        self.assertFalse(report["hardware_access"])

    def test_modified_provenance_rejected(self):
        evidence = json.loads((Path(__file__).resolve().parents[1] /
                               "evidence/bootloader-analysis.json").read_text())
        evidence["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Unexpected evidence"):
            audit_public_evidence(evidence)

    def test_synthetic_descriptor_and_literal_reference(self):
        raw = synthetic_image()
        report = audit_local_image(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
        desc = report["usb_descriptor_candidates"]
        self.assertEqual(len(desc), 1)
        self.assertEqual(desc[0]["pid"], "0x946b")
        self.assertEqual(report["vectors"]["reset_vector"], f"0x{BASE + 0x3001:08x}")
        code = report["control_flow_candidates"]
        self.assertTrue(any(x["descriptor"] == f"0x{BASE + 0x5000:08x}"
                            for x in code["descriptor_literal_references"]))
        self.assertGreater(code["instructions_reached_by_heuristic_walk"], 0)
        self.assertEqual(report["usb_to_writer_reachability"], "NOT DEMONSTRATED")

    def test_missing_descriptor_not_invented(self):
        raw = synthetic_image(descriptor=False)
        report = audit_local_image(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["usb_descriptor_candidates"], [])
        self.assertEqual(report["aligned_pointers_to_descriptor_candidates"], [])
        self.assertEqual(report["control_flow_candidates"]["descriptor_literal_references"], [])

    def test_bad_descriptor_size_packet_and_vendor_rejected(self):
        for offset, value in ((0x5007, 0), (0x5008, 0), (0x5011, 0)):
            raw = bytearray(synthetic_image())
            raw[offset] = value
            data = bytes(raw)
            report = audit_local_image(data, expected_sha256=hashlib.sha256(data).hexdigest(),
                                       walk=False)
            self.assertFalse(report["usb_descriptor_candidates"])

    def test_without_valid_reset_skip_walk(self):
        raw = synthetic_image(vector=False)
        report = audit_local_image(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
        self.assertFalse(report["vectors"]["valid_initial_sp_and_reset"])
        self.assertEqual(report["control_flow_candidates"]["status"], "SKIPPED")

    def test_default_rejects_synthetic_firmware(self):
        self.assertNotEqual(hashlib.sha256(synthetic_image()).hexdigest(), KNOWN_SHA256)
        with self.assertRaisesRegex(ValueError, "Unexpected SHA-256"):
            audit_local_image(synthetic_image())

    def test_truncated_and_extended_firmware_rejected(self):
        raw = synthetic_image()
        for wrong in (raw[:-1], raw+b"\0"):
            with self.subTest(size=len(wrong)), self.assertRaisesRegex(ValueError, "131072"):
                audit_local_image(wrong, expected_sha256=hashlib.sha256(wrong).hexdigest())

    def test_no_walk_skips_code_but_keeps_usb_descriptors(self):
        raw = synthetic_image()
        report = audit_local_image(raw, expected_sha256=hashlib.sha256(raw).hexdigest(), walk=False)
        self.assertEqual(len(report["usb_descriptor_candidates"]), 1)
        self.assertEqual(report["control_flow_candidates"]["status"], "SKIPPED")
        self.assertTrue(report["sha256_verified"])


if __name__ == "__main__":
    unittest.main()
