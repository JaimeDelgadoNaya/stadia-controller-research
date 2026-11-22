"""Synthetic-only regression tests for the OEM-to-CDC descriptor patch auditor."""
import struct
import unittest

from tools.audit_community_bootloader_patch_phase93 import audit, parse_configuration, parse_ivt

OEM_CONFIG = bytes.fromhex(
    "0902500002010080fa080b0001ff0000000904000002ff0000000705870200020007"
    "050702000200080b010103000000090401000203000000092111010001229c000705"
    "830340000607050303400006"
)
CDC_CONFIG = bytes.fromhex(
    "0902550003010080fa0904000002ff00000007058702000200070507020002000904"
    "0100010202000005240010010424020605240601020705820308000709040200020a"
    "0000000705810200020007050102000200"
)
DEVICE = bytes.fromhex("12010002ef020140d1186b94010001020403")


def fixture():
    original = bytearray(0x20000)
    struct.pack_into("<8I", original, 0,
        0x412000D1, 0x60801000, 0, 0, 0x60001020, 0x60001000, 0x60818000, 0)
    original[0xBF78:0xBF78+18] = DEVICE
    original[0x1527C:0x1527C+len(OEM_CONFIG)] = OEM_CONFIG
    original[0xAF48:0xAF58] = bytes.fromhex("4b0200200b6050234b6070477c528160")
    original[0x18000:0x18004] = bytes.fromhex("d4006042")
    candidate = bytearray(original[:0x17028])
    candidate[0x18:0x1C] = b"\x00\x00\x00\x00"
    candidate[0xAF4E] = 0x55
    candidate[0x1527C:0x1527C+len(CDC_CONFIG)] = CDC_CONFIG
    return bytes(original), bytes(candidate)


class CommunityBootloaderPatchPhase93(unittest.TestCase):
    def setUp(self):
        self.original, self.candidate = fixture()
        self.report = audit(self.original, self.candidate)

    def test_ivt_csf_pointer_removed_but_entry_preserved(self):
        self.assertEqual(self.report["original"]["ivt"]["entry"], "0x60801000")
        self.assertEqual(self.report["candidate"]["ivt"]["entry"], "0x60801000")
        self.assertEqual(self.report["original"]["ivt"]["csf"], "0x60818000")
        self.assertEqual(self.report["candidate"]["ivt"]["csf"], "0x0")

    def test_usb_device_descriptor_unchanged(self):
        self.assertTrue(self.report["checks"]["same_device_descriptor"])
        self.assertTrue(self.report["checks"]["same_vid_pid"])
        self.assertEqual(self.report["candidate"]["device"]["vid"], "0x18d1")
        self.assertEqual(self.report["candidate"]["device"]["pid"], "0x946b")

    def test_oem_configuration_is_vendor_plus_hid(self):
        c = self.report["original"]["configuration"]
        self.assertEqual(c["total_length"], 80)
        self.assertEqual(c["bNumInterfaces"], 2)
        self.assertEqual(c["iad_count"], 2)
        self.assertEqual([i["class_code"] for i in c["interfaces"]], [0xFF, 0x03])
        self.assertEqual([e["address"] for e in c["endpoints"]],
                         ["0x87", "0x07", "0x83", "0x03"])

    def test_candidate_configuration_is_vendor_plus_cdc(self):
        c = self.report["candidate"]["configuration"]
        self.assertEqual(c["total_length"], 85)
        self.assertEqual(c["bNumInterfaces"], 3)
        self.assertEqual(c["iad_count"], 0)
        self.assertEqual([i["class_code"] for i in c["interfaces"]], [0xFF, 0x02, 0x0A])
        self.assertEqual(c["cdc_unions"], [{"master": 1, "slaves": [2]}])
        self.assertEqual([e["address"] for e in c["endpoints"]],
                         ["0x87", "0x07", "0x82", "0x81", "0x01"])

    def test_only_expected_three_regions_change(self):
        self.assertEqual(self.report["diff"]["changed_bytes"], 72)
        self.assertEqual(self.report["diff"]["changed_outside_ivt_code_descriptor"], 0)
        self.assertTrue(self.report["checks"]["only_ivt_csf_code_length_and_usb_configuration_changed"])

    def test_code_constant_tracks_configuration_length(self):
        c = self.report["code_patch"]
        self.assertEqual(c["original_descriptor_length_constant"], 0x50)
        self.assertEqual(c["original_thumb_halfword"], "5023")
        self.assertEqual(c["candidate_thumb_halfword"], "5523")
        self.assertEqual(c["candidate_descriptor_length_constant"], 0x55)
        self.assertEqual(c["pointer_literal"], "0x6081527c")
        self.assertTrue(c["pointer_unchanged"])
        self.assertTrue(c["length_matches_configuration"])

    def test_original_csf_removed_from_candidate(self):
        a = self.report["authentication"]
        self.assertEqual(a["original_csf_header_at_0x18000"], "d4006042")
        self.assertFalse(a["candidate_reaches_csf_offset"])
        self.assertFalse(a["candidate_original_signature_verified"])
        self.assertFalse(a["candidate_hab_acceptance_verified"])

    def test_candidate_is_truncated_before_csf(self):
        self.assertEqual(self.report["diff"]["tail_removed_bytes"], 36824)
        self.assertTrue(self.report["checks"]["candidate_truncated_before_original_csf"])
        self.assertFalse(self.report["checks"]["flash_safety_verified"])

    def test_invalid_usb_total_length_rejected(self):
        bad = bytearray(CDC_CONFIG)
        bad[2:4] = (0x7FFF).to_bytes(2, "little")
        with self.assertRaisesRegex(ValueError, "truncated"):
            parse_configuration(bytes(bad), 0)

    def test_invalid_endpoint_count_rejected(self):
        bad = bytearray(CDC_CONFIG)
        # Interface 0 declares two endpoints; make it declare three.
        bad[13] = 3
        with self.assertRaisesRegex(ValueError, "endpoint count"):
            parse_configuration(bytes(bad), 0)

    def test_unknown_cdc_union_interface_rejected(self):
        bad = bytearray(CDC_CONFIG)
        marker = bytes.fromhex("0524060102")
        pos = bad.index(marker)
        bad[pos+4] = 9
        with self.assertRaisesRegex(ValueError, "unknown interface"):
            parse_configuration(bytes(bad), 0)

    def test_invalid_ivt_rejected(self):
        with self.assertRaisesRegex(ValueError, "IVT header"):
            parse_ivt(b"\x00" * 64)


if __name__ == "__main__":
    unittest.main()
