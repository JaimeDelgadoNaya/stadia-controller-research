"""Synthetic phase-17 regression tests; no Google firmware or device needed."""
import hashlib
import struct
import unittest

from tools import audit_vendor_endpoints as m


def fixture():
    data = bytearray(b"\xFF" * m.SIZE)
    for offset, encoded in m.ANCHORS.items():
        raw = bytes.fromhex(encoded)
        data[offset:offset+len(raw)] = raw
    struct.pack_into("<II", data, m.TABLE, *m.CALLBACKS)
    struct.pack_into("<I", data, m.TABLE_LITERAL, m.BASE + m.TABLE)
    struct.pack_into("<I", data, m.RAM_DESCRIPTOR_LITERAL, 0x200000DC)
    data[0x1527C:0x1527C+9] = bytes.fromhex("0902500002010080fa")
    data[0x15296:0x1529D] = bytes.fromhex("07058702000200")
    data[0x1529D:0x152A4] = bytes.fromhex("07050702000200")
    return bytes(data)


def fingerprints(image):
    return {(start, end): hashlib.sha256(image[start:end]).hexdigest()
            for start, end in m.FINGERPRINTS}


def test_audit(image, fingerprints_override=None):
    return m.audit(
        image, expected_sha256=hashlib.sha256(image).hexdigest(),
        fingerprints=fingerprints_override or fingerprints(image),
    )


class VendorEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic = fixture()

    def test_known_real_sha_rejects_synthetic_blob(self):
        with self.assertRaisesRegex(ValueError, "Wrong SHA-256"):
            m.audit(self.synthetic)

    def test_two_registered_callback_addresses(self):
        report = test_audit(self.synthetic)
        self.assertEqual(report["endpoint_registration"]["callbacks_thumb"],
                         ["0x60809e31", "0x6080a06b"])
        self.assertEqual(report["endpoint_registration"]["endpoint_init_target"], "0x60806660")
        self.assertEqual(report["endpoint_registration"]["loop_second_iteration"], "0x60809f7e")
        self.assertFalse(report["hardware_access"])
        self.assertEqual(report["host_bulk_out_to_command_parser"], "NOT TRACED")

    def test_both_endpoint_directions_have_distinct_slots(self):
        report = test_audit(self.synthetic)
        slots = report["endpoint_registration_helper"]["endpoint_slots"]
        self.assertEqual(slots, [
            {"endpoint": "0x87", "index": 15, "handler_offset_from_device": "0xc0",
             "context_offset_from_device": "0xc4"},
            {"endpoint": "0x07", "index": 14, "handler_offset_from_device": "0xb4",
             "context_offset_from_device": "0xb8"},
        ])
        self.assertIn("UNRESOLVED", report["endpoint_registration"][
            "endpoint_direction_to_callback_assignment"])

    def test_endpoint_mapping_rejects_invalid_number(self):
        for ep in [0x08, 0x88, -1, 256, None, True]:
            with self.subTest(ep=ep), self.assertRaises(ValueError):
                m.endpoint_index(ep)

    def test_endpoint_index_covers_both_directions(self):
        for i in range(8):
            self.assertEqual(m.endpoint_index(i), i*2)
            self.assertEqual(m.endpoint_index(i | 0x80), i*2+1)

    def test_unknown_callback_pointer_rejected(self):
        image = bytearray(self.synthetic)
        struct.pack_into("<I", image, m.TABLE, 0x6080AB11)
        with self.assertRaisesRegex(ValueError, "callback pair"):
            test_audit(bytes(image))

    def test_changed_registration_table_literal_rejected(self):
        image = bytearray(self.synthetic)
        struct.pack_into("<I", image, m.TABLE_LITERAL, m.BASE+0x1234)
        with self.assertRaisesRegex(ValueError, "callback table literal"):
            test_audit(bytes(image))

    def test_ram_endpoint_descriptor_source_is_anchored(self):
        image = bytearray(self.synthetic)
        struct.pack_into("<I", image, m.RAM_DESCRIPTOR_LITERAL, 0)
        with self.assertRaisesRegex(ValueError, "RAM endpoint"):
            test_audit(bytes(image))

    def test_corrupted_bulk_out_descriptor_rejected(self):
        image = bytearray(self.synthetic)
        image[0x1529D + 2] = 0x06
        with self.assertRaisesRegex(ValueError, "bulk endpoint"):
            test_audit(bytes(image))

    def test_actual_instruction_anchors_are_enforced(self):
        image = bytearray(self.synthetic)
        image[0x6668] ^= 1
        with self.assertRaisesRegex(ValueError, "Instruction anchor"):
            test_audit(bytes(image))

    def test_region_fingerprint_detects_unanchored_mutation(self):
        image = bytearray(self.synthetic)
        good_fingerprints = fingerprints(self.synthetic)
        image[0x9EFA] ^= 1
        with self.assertRaisesRegex(ValueError, "Machine code region mismatch"):
            test_audit(bytes(image), good_fingerprints)

    def test_truncated_image_rejected(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            test_audit(self.synthetic[:-1])

    def test_output_never_claims_firmware_execution(self):
        result = test_audit(self.synthetic)
        self.assertEqual(result["host_bulk_out_to_flash_writer"], "NOT DEMONSTRATED")
        self.assertEqual(result["signature_bypass"], "NOT DEMONSTRATED")
        self.assertEqual(result["custom_firmware_execution"], "NOT DEMONSTRATED")
        self.assertFalse(result["usb_transactions"])
        self.assertFalse(result["flash_or_efuse_writes"])


if __name__ == "__main__":
    unittest.main()
