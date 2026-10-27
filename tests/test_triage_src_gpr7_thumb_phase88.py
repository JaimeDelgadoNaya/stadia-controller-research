"""Synthetic-only short-path decoder regression tests; not firmware execution."""
import struct
import unittest

from tools.triage_src_gpr7_thumb_phase88 import triage_src_loads
from tools.audit_src_gpr7_writers_phase88 import SRC_BASE, SRC_GPR7, SRC_GPR6


def fixture(store_halfword):
    data=bytearray(bytes([255])*64)
    struct.pack_into("<H",data,0,0x4b01)  # ldr r3, [pc,#4] -> offset 8
    struct.pack_into("<H",data,2,store_halfword)
    struct.pack_into("<I",data,8,SRC_BASE)
    return bytes(data)


class TriageSRCGPR7Tests(unittest.TestCase):
    def test_straightline_thumb_store_to_gpr7_is_candidate_only(self):
        result=triage_src_loads(fixture(0x639a),64,mapped_base=0x60040000)
        self.assertEqual(result["candidate_literal_ldr_encodings"],1)
        self.assertEqual(result["syntactic_store_count"],1)
        self.assertEqual(result["syntactic_stores_to_src_gpr7"][0]["destination_if_straightline"],
                         "0x400f8038")
        self.assertFalse(result["syntactic_stores_to_src_gpr7"][0]["physical_execution_or_bit3_write_proven"])

    def test_str_to_gpr6_is_not_misclassified_as_gpr7(self):
        # immediate 13 words -> 0x34, not 0x38
        result=triage_src_loads(fixture(0x635a),64,mapped_base=0x60040000)
        self.assertEqual(result["syntactic_store_count"],0)
        self.assertEqual(SRC_GPR6+4,SRC_GPR7)

    def test_branch_separating_ldr_and_store_blocks_straightline_inference(self):
        data=bytearray(fixture(0x639a))
        # At offset 2 put a branch to offset 8. Move store to offset 4.
        struct.pack_into("<H",data,2,0xe001)
        struct.pack_into("<H",data,4,0x639a)
        result=triage_src_loads(bytes(data),64,mapped_base=0x60040000)
        self.assertEqual(result["syntactic_store_count"],0)

    def test_unreferenced_raw_base_literal_has_no_load_candidate(self):
        data=bytearray(bytes([255])*64)
        struct.pack_into("<I",data,8,SRC_BASE)
        result=triage_src_loads(bytes(data),64,mapped_base=0x60040000)
        self.assertEqual(result["candidate_literal_ldr_encodings"],0)

    def test_unknown_loader_mapping_does_not_claim_live_execution(self):
        result=triage_src_loads(fixture(0x639a),64,mapped_base=0x20000000)
        self.assertEqual(result["confirmed_reachable_bit3_writers"],0)
        self.assertFalse(result["full_original_control_flow_or_rom_writers_included"])


if __name__=="__main__":
    unittest.main()
