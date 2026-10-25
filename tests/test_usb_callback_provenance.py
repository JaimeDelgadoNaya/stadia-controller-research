"""Synthetic safety/regression tests for phase 16 USB callback provenance."""
import hashlib
import struct
import unittest

from tools import audit_usb_callback_provenance as m


def fixture():
    data = bytearray(b"\xff" * m.SIZE)
    for offset, encoding in m.ANCHORS.items():
        raw = bytes.fromhex(encoding)
        data[offset:offset+len(raw)] = raw
    pointers = {
        m.CDC_VTABLE_LITERAL: m.BASE+m.CDC_VTABLE_OFFSET,
        m.CDC_VTABLE_OFFSET: m.BASE+0x9B29,
        m.CDC_EVENT_TABLE: m.BASE+0x9C59,
        m.VENDOR_EVENT_TABLE: m.BASE+0x9E65,
        0xBBB0: m.VENDOR_CALLBACK_DEFAULT,
        0x9E8C: m.RAM_OBJECT_BASE,
        0x9E90: m.VENDOR_CALLBACK_DEFAULT,
    }
    for offset, val in pointers.items():
        struct.pack_into("<I", data, offset, val)
    for offset, string in (
        (0x14DFB, b"usb_device_cdc.cc\x00"),
        (0x14EBC, b"usb_device_vendor.cc\x00"),
        (0x14E69, b"Vendor usb device unloaded.\x00"),
    ):
        data[offset:offset+len(string)] = string
    return bytes(data)


def audit_fixture(image):
    return m.audit(image, expected_sha256=hashlib.sha256(image).hexdigest())


class UsbCallbackProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = fixture()

    def test_known_sha_rejects_synthetic_image(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            m.audit(self.image)

    def test_synthetic_provenance_passes(self):
        r = audit_fixture(self.image)
        self.assertEqual(r["cdc_object_path"]["first_method_thumb"], "0x60809b29")
        self.assertEqual(r["cdc_object_path"]["512_byte_guard_at"], "0x60809b28")
        self.assertEqual(r["cdc_object_path"]["object_callback_slot"], "0x200090fc")
        self.assertEqual(r["vendor_object_path"]["callback_pointer_ram"], "0x20009168")
        self.assertEqual(r["vendor_object_path"]["default_handler_thumb"], "0x60809e3d")
        self.assertEqual(r["vendor_bulk_out_0x07_to_parser"], "NOT RECONSTRUCTED")
        self.assertFalse(r["hardware_access"])

    def test_cdc_pointer_anchored(self):
        bad = bytearray(self.image)
        struct.pack_into("<I", bad, m.CDC_VTABLE_LITERAL, m.BASE+0x10)
        with self.assertRaisesRegex(ValueError, "Pointer-table change"):
            audit_fixture(bytes(bad))

    def test_vendor_event_pointer_anchored(self):
        bad = bytearray(self.image)
        struct.pack_into("<I", bad, m.VENDOR_EVENT_TABLE, m.BASE+0x9C59)
        with self.assertRaisesRegex(ValueError, "Pointer-table change"):
            audit_fixture(bytes(bad))

    def test_default_vendor_handler_anchored(self):
        bad = bytearray(self.image)
        struct.pack_into("<I", bad, 0xBBB0, m.BASE+0x10)
        with self.assertRaisesRegex(ValueError, "Pointer-table change"):
            audit_fixture(bytes(bad))

    def test_callback_load_instruction_anchored(self):
        bad = bytearray(self.image)
        bad[0x9C46] ^= 1
        with self.assertRaisesRegex(ValueError, "Instruction anchor"):
            audit_fixture(bytes(bad))

    def test_event_to_callback_instruction_anchored(self):
        bad = bytearray(self.image)
        bad[0x9CE4] ^= 1
        with self.assertRaisesRegex(ValueError, "Instruction anchor"):
            audit_fixture(bytes(bad))

    def test_default_vendor_callback_store_anchored(self):
        bad = bytearray(self.image)
        bad[0xBB47] ^= 1
        with self.assertRaisesRegex(ValueError, "Instruction anchor"):
            audit_fixture(bytes(bad))

    def test_missing_source_name_rejected(self):
        bad = bytearray(self.image)
        bad[0x14DFB:0x14DFB+len(b"usb_device_cdc.cc")] = b"x"*len(b"usb_device_cdc.cc")
        with self.assertRaisesRegex(ValueError, "diagnostic string missing"):
            audit_fixture(bytes(bad))

    def test_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            audit_fixture(self.image[:-1])

    def test_direct_store_search_scope_explicit(self):
        r = audit_fixture(self.image)
        self.assertIn("NOT a proof", r["vendor_object_path"]["scope_of_store_search"])
        self.assertEqual(r["vendor_object_path"]["observed_exact_direct_store_opcode_occurrences"],
                         ["0x6080bb46"])

    def test_independent_cdc_and_vendor_event_entries(self):
        r = audit_fixture(self.image)
        self.assertNotEqual(r["cdc_object_path"]["internal_event_switch"],
                            r["vendor_object_path"]["event_handler"])
        self.assertEqual(r["vendor_bulk_out_to_flash_writer"], "NOT DEMONSTRATED")


if __name__ == "__main__":
    unittest.main()
