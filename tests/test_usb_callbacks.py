"""Fully synthetic phase-14 USB parser and callback audit tests.

No Google firmware is stored in this repository.
"""
import hashlib
import struct
import unittest

from tools.audit_usb_callbacks import (
    BASE, SIZE, CONFIG_OFFSET, DEVICE_OFFSET, EVENT_TABLE_OFFSET,
    SECOND_EVENT_TABLE_OFFSET, OBJECT_BASE, CALLBACK_ROUTINE, DEFAULT_HANDLER,
    audit, parse_configuration, parse_device_descriptor,
)


def fixture_image():
    data = bytearray(b"\xff" * SIZE)
    data[DEVICE_OFFSET:DEVICE_OFFSET+18] = bytes.fromhex(
        "12 01 00 02 ef 02 01 40 d1 18 6b 94 01 00 01 02 04 03"
    )
    descs = [
        bytes.fromhex("09 02 50 00 02 01 00 80 fa"),
        bytes.fromhex("08 0b 00 01 ff 00 00 00"),
        bytes.fromhex("09 04 00 00 02 ff 00 00 00"),
        bytes.fromhex("07 05 87 02 00 02 00"),
        bytes.fromhex("07 05 07 02 00 02 00"),
        bytes.fromhex("08 0b 01 01 03 00 00 00"),
        bytes.fromhex("09 04 01 00 02 03 00 00 00"),
        bytes.fromhex("09 21 11 01 00 01 22 9c 00"),
        bytes.fromhex("07 05 83 03 40 00 06"),
        bytes.fromhex("07 05 03 03 40 00 06"),
    ]
    assert len(b"".join(descs)) == 80
    data[CONFIG_OFFSET:CONFIG_OFFSET+80] = b"".join(descs)
    for at, pointer in (
        (EVENT_TABLE_OFFSET, CALLBACK_ROUTINE | 1),
        (SECOND_EVENT_TABLE_OFFSET, 0x60809C59),
        (0x9E8C, OBJECT_BASE), (0x9E90, DEFAULT_HANDLER),
        (0xBBB0, DEFAULT_HANDLER), (0xAF54, BASE+CONFIG_OFFSET),
    ):
        struct.pack_into("<I", data, at, pointer)
    for at, pattern in (
        (0x9E64, "7f29"), (0x9E6E, "d0f8f035"),
        (0x9E76, "d0f8f405"), (0x9E7A, "9847"),
        (0xBB46, "c4f8f035"), (0xBB68, "c4f8f455"),
    ):
        raw = bytes.fromhex(pattern)
        data[at:at+len(raw)] = raw
    return bytes(data)


def audit_fixture(blob):
    return audit(blob, expected_sha256=hashlib.sha256(blob).hexdigest())


class UsbCallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = fixture_image()

    def test_synthetic_end_to_end(self):
        report = audit_fixture(self.blob)
        self.assertEqual(report["usb_device_descriptor"]["pid"], "0x946b")
        self.assertEqual(report["usb_configuration"]["total_length"], 80)
        self.assertEqual(report["usb_to_flash_writer"], "NOT DEMONSTRATED")
        self.assertFalse(report["hardware_access"])
        self.assertFalse(report["flash_operations"])

    def test_interface_endpoint_geometry(self):
        interfaces = audit_fixture(self.blob)["usb_configuration"]["interfaces"]
        self.assertEqual(len(interfaces), 2)
        self.assertEqual((interfaces[0]["number"], interfaces[0]["class"]), (0, "0xff"))
        self.assertEqual((interfaces[1]["number"], interfaces[1]["class"]), (1, "0x03"))
        vendor = interfaces[0]["endpoints"]
        self.assertEqual([(e["address"], e["transfer"], e["max_packet_bytes"]) for e in vendor],
                         [("0x87", "bulk", 512), ("0x07", "bulk", 512)])
        hid = interfaces[1]["endpoints"]
        self.assertEqual([e["address"] for e in hid], ["0x83", "0x03"])
        self.assertEqual(interfaces[1]["hid_report_descriptor_bytes"], 156)

    def test_device_descriptor_requires_exact_length_and_header(self):
        good = self.blob[DEVICE_OFFSET:DEVICE_OFFSET+18]
        with self.assertRaises(ValueError):
            parse_device_descriptor(good[:-1])
        with self.assertRaises(ValueError):
            parse_device_descriptor(b"\x00" + good[1:])

    def test_corrupt_config_length_rejected(self):
        conf = bytearray(self.blob[CONFIG_OFFSET:CONFIG_OFFSET+80])
        conf[2:4] = b"\x00\x50"
        with self.assertRaises(ValueError):
            parse_configuration(bytes(conf))

    def test_endpoint_count_mismatch_rejected(self):
        conf = bytearray(self.blob[CONFIG_OFFSET:CONFIG_OFFSET+80])
        conf[0x11+4] = 3  # vendor interface: offset 0x11, bNumEndpoints at +4
        with self.assertRaisesRegex(ValueError, "endpoint count"):
            parse_configuration(bytes(conf))

    def test_duplicate_endpoint_rejected(self):
        conf = bytearray(self.blob[CONFIG_OFFSET:CONFIG_OFFSET+80])
        conf[0x21+2] = 0x87  # second vendor endpoint at offset 0x21
        with self.assertRaisesRegex(ValueError, "Duplicate endpoint"):
            parse_configuration(bytes(conf))

    def test_wrong_sha_rejected_by_default(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit(self.blob)

    def test_wrong_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            audit_fixture(self.blob[:-1])

    def test_unexpected_vendor_event_target_rejected(self):
        image = bytearray(self.blob)
        struct.pack_into("<I", image, EVENT_TABLE_OFFSET, 0x60809C59)
        with self.assertRaisesRegex(ValueError, "Vendor event callback"):
            audit_fixture(bytes(image))

    def test_changed_machine_instruction_rejected(self):
        image = bytearray(self.blob)
        image[0x9E7A] ^= 1
        with self.assertRaisesRegex(ValueError, "instruction anchor"):
            audit_fixture(bytes(image))

    def test_config_pointer_reference_identified(self):
        refs = audit_fixture(self.blob)["configuration_pointer_words"]
        self.assertIn("0x6080af54", refs)

    def test_unsupported_device_identifier_rejected(self):
        image = bytearray(self.blob)
        image[DEVICE_OFFSET+10] = 0x00
        with self.assertRaisesRegex(ValueError, "VID/PID"):
            audit_fixture(bytes(image))


if __name__ == "__main__":
    unittest.main()
