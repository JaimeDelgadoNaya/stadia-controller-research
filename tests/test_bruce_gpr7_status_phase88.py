"""Synthetic original instruction pin regression tests, not hardware execution."""
import struct
import unittest

from tools.audit_bruce_gpr7_status_phase88 import (
    BRUCE_XIP_BASE,LITERAL_OFFSET,ORIGINAL_THUMB,SOURCE_OFFSET,
    STATUS_IF_EQ,STATUS_IF_NE,inspect_original_fragment,audit
)
from tools.audit_src_gpr7_writers_phase88 import SRC_BASE, SRC_GPR7,UPDATE_BIT


def synthetic():
    data=bytearray(bytes([255])*(LITERAL_OFFSET+64))
    data[SOURCE_OFFSET:SOURCE_OFFSET+len(ORIGINAL_THUMB)]=ORIGINAL_THUMB
    struct.pack_into("<I",data,LITERAL_OFFSET,SRC_BASE)
    return bytes(data)


class SignedBruceGPR7StatusTests(unittest.TestCase):
    def test_pinned_static_fragment_reconstructs_correct_destination(self):
        d=inspect_original_fragment(synthetic())
        self.assertEqual(d["site_start"],"0x60078a1c")
        self.assertEqual(d["computed_destination"],"0x400f8038")
        self.assertEqual(d["source_base"],"0x400f8000")
        self.assertEqual(d["literal_file_offset"],"0x38abc")
        self.assertEqual(d["register_name"],"SRC_GPR7")

    def test_exact_conditional_status_values_not_update_bit(self):
        d=inspect_original_fragment(synthetic())
        self.assertEqual((STATUS_IF_EQ,STATUS_IF_NE),(5,6))
        self.assertEqual((d["value_when_equal"],d["value_when_not_equal"]),(5,6))
        self.assertFalse(d["either_value_sets_bootloader_update_bit3"])
        self.assertEqual((STATUS_IF_EQ|STATUS_IF_NE)&UPDATE_BIT,0)

    def test_mutated_thumb_bytes_rejected(self):
        for i in range(len(ORIGINAL_THUMB)):
            data=bytearray(synthetic())
            data[SOURCE_OFFSET+i]^=1
            with self.subTest(i=i):
                with self.assertRaises(ValueError):
                    inspect_original_fragment(bytes(data))

    def test_mutated_base_address_rejected(self):
        data=bytearray(synthetic())
        struct.pack_into("<I",data,LITERAL_OFFSET,SRC_GPR7)
        with self.assertRaisesRegex(ValueError,"literal mismatch"):
            inspect_original_fragment(bytes(data))

    def test_sha256_pin_enforced_before_source_claim(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            audit(synthetic())

    def test_source_never_proves_usb_or_reset_reachability(self):
        d=inspect_original_fragment(synthetic())
        self.assertEqual(d["host_usb_controls_condition"],"NOT_ESTABLISHED")
        self.assertEqual(d["hardware_execution_or_warm_reset_delivery"],"NOT_OBSERVED")


if __name__=="__main__":
    unittest.main()
