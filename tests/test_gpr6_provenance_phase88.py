"""Phase 88: offline source/provenance checks, no controller I/O."""
import copy
import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.audit_gpr6_provenance_phase88 import (
    BRUCE_XIP_BASE,GPR6,GPR6_BASE,
    BRUCE_WRITER_OFFSET,BRUCE_WRITER_BYTES,BRUCE_WRITER_LITERAL_OFFSET,
    audit,census_bootloader_selected,census_bruce_literals,
    decode_pinned_bruce_gpr6_status_writer
)

RECORD=Path(__file__).resolve().parents[1]/"evidence/bootloader-analysis.json"
SPAN=0xff030


def synthetic_image(*placements):
    data=bytearray(b"\xff"*(SPAN+64))
    for offset,constant in placements:
        struct.pack_into("<I",data,offset,constant)
    return bytes(data)


def synthetic_image_with_bruce_writer(*placements):
    data=bytearray(synthetic_image(*placements))
    data[BRUCE_WRITER_OFFSET:BRUCE_WRITER_OFFSET+len(BRUCE_WRITER_BYTES)]=BRUCE_WRITER_BYTES
    struct.pack_into("<I",data,BRUCE_WRITER_LITERAL_OFFSET,GPR6_BASE)
    return bytes(data)


class GPR6ProvenancePhase88Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record=json.loads(RECORD.read_text(encoding="utf-8"))

    def signed_scan(self,image):
        with patch("tools.audit_gpr6_provenance_phase88.audit_signed_bruce",
                   return_value={"sample_sha256":"synthetic-test-not-an-original"}):
            return census_bruce_literals(image)

    def test_bruce_exact_gpr6_base_and_address_words_detected(self):
        r=self.signed_scan(synthetic_image((0x100,GPR6_BASE),(0x200,GPR6)))
        self.assertEqual(r["literal_counts"]["src_register_block_base"],1)
        self.assertEqual(r["literal_counts"]["src_gpr6_full_address"],1)
        self.assertEqual(r["literal_hits"][0]["file_offset"],"0x100")
        self.assertFalse(r["literal_hits"][1]["verified_instruction_use"])
        self.assertEqual(r["confirmed_writers_of_gpr6_bit3"],0)

    def test_bruce_outside_pre_csf_is_excluded(self):
        r=self.signed_scan(synthetic_image((SPAN+12,GPR6)))
        self.assertEqual(sum(r["literal_counts"].values()),0)

    def test_bruce_data_byte_alignment_does_not_fake_literal(self):
        r=self.signed_scan(synthetic_image((0x101,GPR6_BASE)))
        self.assertEqual(sum(r["literal_counts"].values()),0)

    def test_bruce_pc_relative_load_candidate_is_not_execution_proof(self):
        data=bytearray(synthetic_image((0x108,GPR6_BASE)))
        struct.pack_into("<H",data,0x100,0x4801) # pc at 0x104, +4 -> 0x108
        r=self.signed_scan(bytes(data))
        self.assertEqual(len(r["literal_hits"]),1)
        c=r["literal_hits"][0]["syntactic_thumb_load_candidates"]
        self.assertEqual(len(c),1)
        self.assertEqual(c[0]["potential_instruction_file_offset"],"0x100")
        self.assertFalse(c[0]["instruction_boundary_verified"])
        self.assertFalse(r["literal_hits"][0]["proven_gpr6_bit3_writer"])

    def test_signed_bruce_status_writer_is_5_or_6_not_bit3(self):
        d=decode_pinned_bruce_gpr6_status_writer(synthetic_image_with_bruce_writer())
        self.assertEqual(d["target_register"],"0x400f8038")
        self.assertEqual(d["possible_written_values"],[5,6])
        self.assertFalse(d["bit3_set_by_either_value"])
        self.assertTrue(d["verified_instruction_sequence"])
        self.assertFalse(d["runtime_execution_or_host_origin_confirmed"])

    def test_bruce_writer_mutations_and_wrong_base_rejected(self):
        original=synthetic_image_with_bruce_writer()
        for at in range(BRUCE_WRITER_OFFSET,BRUCE_WRITER_OFFSET+len(BRUCE_WRITER_BYTES)):
            tampered=bytearray(original)
            tampered[at]^=1
            with self.subTest(byte_offset=hex(at)):
                with self.assertRaisesRegex(ValueError,"pin mismatch"):
                    decode_pinned_bruce_gpr6_status_writer(bytes(tampered))
        wrong=bytearray(original)
        struct.pack_into("<I",wrong,BRUCE_WRITER_LITERAL_OFFSET,GPR6)
        with self.assertRaisesRegex(ValueError,"literal mismatch"):
            decode_pinned_bruce_gpr6_status_writer(bytes(wrong))

    def test_bruce_writer_report_is_not_usb_trigger(self):
        with patch("tools.audit_gpr6_provenance_phase88.audit_signed_bruce",
                   return_value={"sample_sha256":"synthetic-test-not-an-original"}):
            d=audit(synthetic_image_with_bruce_writer(),self.record)
        self.assertFalse(d["signed_bruce_status_writer"]["bit3_set_by_either_value"])
        self.assertFalse(d["bootloader_selected_original"]["host_usb_writer_proven"])

    def test_bootloader_selected_has_clear_and_unrelated_status_only(self):
        r=census_bootloader_selected(self.record)
        self.assertEqual(r["unambiguous_selected_bit3_setters"],0)
        self.assertEqual({x["site"] for x in r["all_selected_str_offset_0x38_shapes"]},
                         {"0x60801f14","0x6080286a"})
        self.assertEqual({x["address"] for x in r["pinned_gpr6_accesses"]},
                         {"0x60802866","0x6080286a","0x60801f14"})
        self.assertFalse(r["complete_bootloader_writer_census"])
        self.assertFalse(r["host_usb_writer_proven"])

    def test_mutated_selected_gpr6_store_rejected_by_prior_pins(self):
        records=copy.deepcopy(self.record)
        for f in records["functions"]:
            for i in f["instructions"]:
                if i["address"]=="0x60801f14":
                    i["bytes"]="ffff"
        with self.assertRaises(ValueError):
            census_bootloader_selected(records)

    def test_original_bruce_sha_gate_not_skipped(self):
        with self.assertRaises(ValueError):
            census_bruce_literals(synthetic_image((0x100,GPR6_BASE)))

    def test_input_type_and_bound_checked(self):
        with self.assertRaises((ValueError,TypeError)):
            census_bruce_literals(None)

    def test_no_unsupported_live_execution_claim(self):
        with patch("tools.audit_gpr6_provenance_phase88.audit_signed_bruce",
                   return_value={"sample_sha256":"synthetic-test-not-an-original"}):
            r=audit(synthetic_image_with_bruce_writer((0x100,GPR6)),self.record)
        self.assertFalse(r["device_connected"])
        self.assertFalse(r["firmware_written"])
        self.assertFalse(r["bootloader_selected_original"]["host_usb_writer_proven"])
        self.assertFalse(r["bruce_signed_original"]["signed_bruce_xip_to_bootloader_trigger_proven"])


if __name__=="__main__":
    unittest.main()
