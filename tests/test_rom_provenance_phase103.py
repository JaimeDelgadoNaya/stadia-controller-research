"""Strictly offline provenance-gate tests: all candidate samples synthetic."""
import unittest
from research.phase103.triage_rom_origin import (
    SIZE, PUBLIC_RT1060_SHA, OWNER_EXTERNAL_BOOTLOADER_A_SHA,
    OWNER_EXTERNAL_BOOTLOADER_B_SHA, KNOWN_EXTERNAL_FLASH_SHA, classify,
)


class ProvenanceGatePhase103Tests(unittest.TestCase):
    def test_01_no_candidate(self):
        self.assertEqual(classify(None)["status"], "CANDIDATE_MISSING")

    def test_02_wrong_size(self):
        self.assertEqual(classify(b"x")["status"], "REJECT_WRONG_SIZE")

    def test_03_all_ff_slot(self):
        self.assertEqual(classify(bytes([255])*SIZE)["status"],
                         "REJECT_KNOWN_EXTERNAL_FLASH")

    def test_04_all_zero_slot(self):
        self.assertEqual(classify(bytes(SIZE))["status"], "REJECT_BLANK")

    def test_05_flexspi_fcb_at_start(self):
        b=bytearray(b"\x32"*SIZE);b[0:4]=b"FCFB"
        self.assertEqual(classify(bytes(b))["status"], "REJECT_FLEXSPI_NOR_HEADER")

    def test_06_flexspi_fcb_at_header_offset(self):
        b=bytearray(b"\x32"*SIZE);b[0x1000:0x1004]=b"FCFB"
        self.assertEqual(classify(bytes(b))["status"], "REJECT_FLEXSPI_NOR_HEADER")

    def test_07_signed_image_ivt_at_start(self):
        b=bytearray(b"\x32"*SIZE);b[0:4]=bytes.fromhex("d1002041")
        self.assertEqual(classify(bytes(b))["status"], "SUSPECT_BOOT_IMAGE_IVT")

    def test_08_signed_image_ivt_at_0x1000(self):
        b=bytearray(b"\x32"*SIZE);b[0x1000:0x1004]=bytes.fromhex("d1002041")
        self.assertEqual(classify(bytes(b))["status"], "SUSPECT_BOOT_IMAGE_IVT")

    def test_09_declared_external_rejected(self):
        z=classify(b"x"*SIZE, manifest={"source_kind":"external_nor_flash"})
        self.assertEqual(z["status"],"REJECT_DECLARED_EXTERNAL_SOURCE")

    def test_10_self_declared_rom_not_authenticated(self):
        z=classify(b"x"*SIZE, manifest={"source_kind":"declared_internal_mask_rom",
            "acquisition_record":"synthetic claim","device_observation":"synthetic"})
        self.assertEqual(z["status"],"UNVERIFIED_INTERNAL_ROM_DECLARATION")
        self.assertFalse(z["physical_origin_authenticated"])
        self.assertFalse(z["stadia_internal_rom_identified"])

    def test_11_unknown_bytes_not_rom(self):
        z=classify(b"x"*SIZE)
        self.assertEqual(z["status"],"UNKNOWN_128K_IMAGE_NO_PROVENANCE")

    def test_12_reject_corrupted_public_reference(self):
        with self.assertRaisesRegex(ValueError, "exact public"):
            classify(b"x"*SIZE,reference=b"x"*SIZE)

    def test_13_no_unrecognized_manifest_type(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            classify(b"x"*SIZE,manifest="fakerom")

    def test_14_no_unsupported_source_kind(self):
        with self.assertRaisesRegex(ValueError,"Unknown source_kind"):
            classify(b"x"*SIZE,manifest={"source_kind":"silicon_trusted_and_hab_unlocked"})

    def test_15_known_owner_flash_hashes_are_pinned(self):
        self.assertIn(OWNER_EXTERNAL_BOOTLOADER_A_SHA, KNOWN_EXTERNAL_FLASH_SHA)
        self.assertIn(OWNER_EXTERNAL_BOOTLOADER_B_SHA, KNOWN_EXTERNAL_FLASH_SHA)
        self.assertNotIn(PUBLIC_RT1060_SHA, KNOWN_EXTERNAL_FLASH_SHA)

    def test_16_no_external_evidence_becomes_execution(self):
        for src in [b"x"*SIZE,b"\xff"*SIZE,b"\x00"*SIZE]:
            v=classify(src)
            self.assertFalse(v["actual_stadia_exploit_tested"])
            self.assertFalse(v["safe_for_automatic_exploit_claim"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
