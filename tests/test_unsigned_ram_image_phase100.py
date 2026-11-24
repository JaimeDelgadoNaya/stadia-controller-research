"""Eight structurally focused, synthetic tests for unsigned RAM image packaging."""
import hashlib
import struct
import unittest
from research.phase100.build_unsigned_ram_image import (
    LOAD_BASE, IMAGE_SIZE, IVT_OFFSET, BOOT_DATA_OFFSET,
    DEMO_SHA256, build_demo_image, inspect_demo_image,
)

DEMO = bytes.fromhex("00000120090000205a2001490860fee714000020")


class ImageStructurePhase100Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = build_demo_image(DEMO)

    def test_01_correct_source_hash(self):
        self.assertEqual(hashlib.sha256(DEMO).hexdigest(), DEMO_SHA256)

    def test_02_image_size(self):
        self.assertEqual(len(self.image), IMAGE_SIZE)

    def test_03_correct_ivt_header(self):
        self.assertEqual(struct.unpack_from("<I", self.image, IVT_OFFSET)[0],
                         0x412000D1)

    def test_04_entry_address_thumb(self):
        self.assertEqual(struct.unpack_from("<I", self.image, IVT_OFFSET+4)[0],
                         LOAD_BASE+9)

    def test_05_bootdata_consistent(self):
        self.assertEqual(struct.unpack_from("<3I", self.image, BOOT_DATA_OFFSET),
                         (LOAD_BASE, IMAGE_SIZE, 0))

    def test_06_unsigned_no_dcd(self):
        v = inspect_demo_image(self.image)
        self.assertTrue(v["csf_pointer_is_null"])
        self.assertTrue(v["dcd_pointer_is_null"])
        self.assertFalse(v["bootrom_acceptance_proven"])

    def test_07_changed_source_rejected(self):
        changed = bytearray(DEMO)
        changed[-1] ^= 1
        with self.assertRaises(ValueError):
            build_demo_image(bytes(changed))

    def test_08_tampered_ivt_rejected(self):
        changed = bytearray(self.image)
        changed[IVT_OFFSET+6] ^= 1
        with self.assertRaises(ValueError):
            inspect_demo_image(bytes(changed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
