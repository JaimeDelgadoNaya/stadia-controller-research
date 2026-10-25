"""Phase-18 synthetic regression tests. No proprietary images or USB access."""
import hashlib
import struct
import unittest

from tools import audit_endpoint_ram_init as m


def fixture():
    data = bytearray([0xFF] * m.IMAGE_BYTES)
    for at, enc in m.ANCHORS.items():
        raw = bytes.fromhex(enc)
        data[at:at+len(raw)] = raw
    for offset, val in (
        (m.COPY_SOURCE_LITERAL, m.BASE+m.FLASH_INITIALIZER),
        (m.COPY_START_LITERAL, m.RAM_INITIALIZER),
        (m.COPY_END_LITERAL, m.RAM_END),
        (m.ENDPOINT_RAM_LITERAL, m.RAM_ENDPOINT_0+4),
        (m.CALLBACK_TABLE_LITERAL, m.BASE+m.CALLBACK_TABLE),
    ):
        struct.pack_into("<I", data, offset, val)
    struct.pack_into("<II", data, m.CALLBACK_TABLE, *m.EXPECTED_CALLBACKS)
    data[m.FLASH_INITIALIZER+0xD8:m.FLASH_INITIALIZER+0xE0] = bytes.fromhex(
        "87 02 00 02 07 02 00 02")
    data[m.VENDOR_EP_DESCRIPTOR_0:m.VENDOR_EP_DESCRIPTOR_0+7] = bytes.fromhex(
        "07 05 87 02 00 02 00")
    data[m.VENDOR_EP_DESCRIPTOR_1:m.VENDOR_EP_DESCRIPTOR_1+7] = bytes.fromhex(
        "07 05 07 02 00 02 00")
    return bytes(data)


def synthetic_fingerprints(data):
    return {(s,e): hashlib.sha256(data[s:e]).hexdigest() for s,e in m.FINGERPRINTS}


def offline_synthetic(data, fingerprints=None):
    return m.audit(data,
                   expected_sha256=hashlib.sha256(data).hexdigest(),
                   fingerprints=(fingerprints if fingerprints is not None
                                 else synthetic_fingerprints(data)))


class EndpointRamInitializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = fixture()

    def test_production_sha_refuses_synthetic_binary(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.audit(self.image)

    def test_startup_copy_is_400_bytes(self):
        result = offline_synthetic(self.image)
        self.assertEqual(result["startup_initializer"]["bytes_copied"], 0x190)
        self.assertEqual(result["startup_initializer"]["source_flash"], "0x608161e0")
        self.assertEqual(result["startup_initializer"]["destination_ram_end_exclusive"],
                         "0x20000190")
        self.assertFalse(result["device_access"])

    def test_direction_callback_assignment(self):
        records = offline_synthetic(self.image)["vendor_endpoint_registration"]["records"]
        self.assertEqual([(x["endpoint"], x["registered_callback_function"],
                           x["usb_internal_endpoint_slot"]) for x in records],
                         [("0x87", "0x60809e30", 15), ("0x07", "0x6080a06a", 14)])
        self.assertEqual(records[0]["flash_source"], "0x608162b8")
        self.assertEqual(records[1]["flash_source"], "0x608162bc")

    def test_changed_data_copy_literals_rejected(self):
        for at in (m.COPY_SOURCE_LITERAL, m.COPY_START_LITERAL, m.COPY_END_LITERAL):
            with self.subTest(address=hex(at)):
                altered = bytearray(self.image)
                struct.pack_into("<I", altered, at, 0)
                with self.assertRaisesRegex(ValueError, "copy literals"):
                    offline_synthetic(bytes(altered))

    def test_changed_endpoint_record_order_rejected(self):
        altered = bytearray(self.image)
        altered[m.FLASH_INITIALIZER+0xD8] = 0x07
        with self.assertRaisesRegex(ValueError, "endpoint ordering"):
            offline_synthetic(bytes(altered))

    def test_changed_usb_descriptor_rejected(self):
        altered = bytearray(self.image)
        altered[m.VENDOR_EP_DESCRIPTOR_1+2] = 0x06
        with self.assertRaisesRegex(ValueError, "USB configuration descriptor"):
            offline_synthetic(bytes(altered))

    def test_callback_order_rejected(self):
        altered = bytearray(self.image)
        struct.pack_into("<II", altered, m.CALLBACK_TABLE, *reversed(m.EXPECTED_CALLBACKS))
        with self.assertRaisesRegex(ValueError, "callback pointers"):
            offline_synthetic(bytes(altered))

    def test_callback_table_pointer_change_rejected(self):
        altered = bytearray(self.image)
        struct.pack_into("<I", altered, m.CALLBACK_TABLE_LITERAL, m.BASE+0x1234)
        with self.assertRaisesRegex(ValueError, "callback table pointer"):
            offline_synthetic(bytes(altered))

    def test_modified_copy_opcode_rejected(self):
        altered = bytearray(self.image)
        altered[0x160A] ^= 1
        with self.assertRaisesRegex(ValueError, "Machine-code anchor"):
            offline_synthetic(bytes(altered))

    def test_region_fingerprint_detects_unanchored_modification(self):
        altered = bytearray(self.image)
        altered[0x9F01] ^= 1
        with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
            offline_synthetic(bytes(altered), synthetic_fingerprints(self.image))

    def test_invalid_image_size_rejected(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            offline_synthetic(self.image[:-1])

    def test_out_and_in_have_distinct_controller_slots(self):
        self.assertEqual(m.endpoint_register_index(0x07), 14)
        self.assertEqual(m.endpoint_register_index(0x87), 15)
        for value in (-1, 256, True, 0x08, 0x88):
            with self.subTest(address=value), self.assertRaises(ValueError):
                m.endpoint_register_index(value)

    def test_dynamic_handler_and_hab_bypass_remain_unresolved(self):
        r = offline_synthetic(self.image)
        self.assertEqual(r["bulk_out_0x07_next_indirect"]["final_callback_target"],
                         "NOT RESOLVED")
        self.assertEqual(r["host_to_flash_writer"], "NOT DEMONSTRATED")
        self.assertEqual(r["hab_bypass"], "NOT DEMONSTRATED")
        self.assertEqual(r["custom_firmware_execution"], "NOT DEMONSTRATED")
        self.assertFalse(r["flash_or_fuse_operations"])


if __name__ == "__main__":
    unittest.main()
