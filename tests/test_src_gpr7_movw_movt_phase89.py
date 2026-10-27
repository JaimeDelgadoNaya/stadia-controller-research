"""Synthetic-only checks for Thumb-2 synthesized SRC address survey phase89."""
import struct
import unittest
from tools.audit_src_gpr7_movw_movt_phase89 import (
    SRC_BASE,SRC_GPR6,SRC_GPR7,
    analyze_encodings,audit,decode_thumb_mov_imm,decode_thumb_store,
    BRUCE_LONE_MOVW_OFFSET,BRUCE_LONE_MOVW_RETURN_BYTES,classify_bruce_lone_movw
)


def thumb_mov(kind,reg,imm):
    """Produce deterministic encoding fixture: Thumb MOVW / MOVT T1."""
    if kind not in ("movw","movt") or not 0<=reg<=14 or not 0<=imm<=0xffff:
        raise ValueError("invalid fixture")
    h1=(0xf240 if kind=="movw" else 0xf2c0)|((imm>>12)&15)|(((imm>>11)&1)<<10)
    h2=(reg<<8)|(((imm>>8)&7)<<12)|(imm&255)
    return struct.pack("<HH",h1,h2)


def fixture(*,low=0x8000,high=0x400f,reg=3,step=4,store_offset=8,disp=0x38,
            value_reg=2,kind="str_t1"):
    data=bytearray(b"\xff"*256)
    data[0:4]=thumb_mov("movw",reg,low)
    data[step:step+4]=thumb_mov("movt",reg,high)
    if kind=="str_t1":
        if reg>7 or value_reg>7 or disp%4 or disp>124:
            raise ValueError("unsupported test str")
        hw=0x6000|((disp//4)<<6)|(reg<<3)|value_reg
        struct.pack_into("<H",data,store_offset,hw)
    if kind=="str_t3":
        struct.pack_into("<HH",data,store_offset,0xf8c0|reg,
                         (value_reg<<12)|disp)
    return bytes(data)


class MOVWPhase89Tests(unittest.TestCase):
    def test_decode_movw_movt_immediates(self):
        b=thumb_mov("movw",3,0x8000)+thumb_mov("movt",3,0x400f)
        self.assertEqual((decode_thumb_mov_imm(b,0)["kind"],
                          decode_thumb_mov_imm(b,0)["imm16"]),
                         ("movw",0x8000))
        self.assertEqual((decode_thumb_mov_imm(b,4)["kind"],
                          decode_thumb_mov_imm(b,4)["imm16"]),
                         ("movt",0x400f))

    def test_adjacent_base_pair_plus_str_t1_is_only_candidate(self):
        r=analyze_encodings(fixture(),256)
        self.assertEqual(r["pair_count"],1)
        self.assertEqual(r["store_shape_count"],1)
        p=r["same_register_ordered_pairs"][0]
        self.assertTrue(p["movw_movt_adjacent"])
        self.assertEqual(p["computed_constant_if_same_live_register"],"0x400f8000")
        self.assertFalse(p["actual_reaching_definition_proven"])
        self.assertFalse(r["possibly_computed_gpr7_store_shapes"][0]["runtime_store_proven"])
        self.assertEqual(r["confirmed_gpr7_bit3_writer_count"],0)

    def test_direct_gpr7_pair_and_str_zero_imm(self):
        r=analyze_encodings(fixture(low=0x8038,disp=0),256)
        self.assertEqual(r["pair_count"],1)
        self.assertEqual(r["store_shape_count"],1)
        self.assertEqual(r["possibly_computed_gpr7_store_shapes"][0][
            "possible_effective_address"],"0x400f8038")

    def test_gpr6_pair_is_not_misidentified_as_gpr7(self):
        r=analyze_encodings(fixture(low=0x8034,disp=0),256)
        self.assertEqual(r["pair_count"],1)
        self.assertEqual(r["store_shape_count"],0)

    def test_str_w_t3_offset_recognized(self):
        raw=fixture(kind="str_t3")
        st=decode_thumb_store(raw,8)
        self.assertEqual((st["kind"],st["base_reg"],st["disp"],st["value_reg"]),
                         ("str_imm_t3",3,0x38,2))
        r=analyze_encodings(raw,256)
        self.assertEqual(r["store_shape_count"],1)

    def test_pair_must_use_same_register(self):
        data=bytearray(fixture())
        data[4:8]=thumb_mov("movt",4,0x400f)
        r=analyze_encodings(bytes(data),256)
        self.assertEqual(r["pair_count"],0)

    def test_wrong_upper_half_never_forms_src(self):
        r=analyze_encodings(fixture(high=0x400e),256)
        self.assertEqual(r["pair_count"],0)

    def test_reverse_order_rejected(self):
        raw=bytearray(fixture())
        raw[0:4],raw[4:8]=raw[4:8],raw[0:4]
        r=analyze_encodings(bytes(raw),256)
        self.assertEqual(r["pair_count"],0)

    def test_wide_gap_only_captured_with_window_and_not_proven(self):
        r=analyze_encodings(fixture(step=40,store_offset=44),256)
        self.assertEqual(r["pair_count"],1)
        self.assertFalse(r["same_register_ordered_pairs"][0]["movw_movt_adjacent"])
        self.assertFalse(r["same_register_ordered_pairs"][0]["actual_reaching_definition_proven"])
        r2=analyze_encodings(fixture(step=40,store_offset=44),256,pair_window=20)
        self.assertEqual(r2["pair_count"],0)

    def test_pre_csf_cutoff_excludes_movt_after_boundary(self):
        b=fixture(step=32,store_offset=36)
        r=analyze_encodings(b,32)
        self.assertEqual(r["pair_count"],0)

    def test_no_literal_word_required_for_mov_pair(self):
        b=fixture()
        self.assertNotIn(struct.pack("<I",SRC_BASE),b)
        r=analyze_encodings(b,256)
        self.assertEqual(r["store_shape_count"],1)

    def test_clobber_and_branch_are_not_established_by_raw_pair_scan(self):
        b=bytearray(fixture(step=40,store_offset=44))
        struct.pack_into("<H",b,8,0xe000)  # branch between candidate encodings
        r=analyze_encodings(bytes(b),256)
        self.assertEqual(r["pair_count"],1)
        self.assertFalse(r["same_register_ordered_pairs"][0][
            "actual_reaching_definition_proven"])

    def test_pinned_original_scalar_return_not_src_address(self):
        b=bytearray(b"\xff"*(BRUCE_LONE_MOVW_OFFSET+8))
        b[BRUCE_LONE_MOVW_OFFSET:BRUCE_LONE_MOVW_OFFSET+6]=BRUCE_LONE_MOVW_RETURN_BYTES
        d=classify_bruce_lone_movw(bytes(b))
        self.assertEqual(d["original_bytes"],"48f200007047")
        self.assertEqual(d["static_instructions"],["MOVW R0, #0x8000","BX LR"])
        self.assertFalse(d["gpr7_bit3_write_proven"])
        self.assertFalse(d["control_flow_reachability_proven"])

    def test_altered_signed_movw_return_is_rejected(self):
        b=bytearray(b"\xff"*(BRUCE_LONE_MOVW_OFFSET+8))
        b[BRUCE_LONE_MOVW_OFFSET:BRUCE_LONE_MOVW_OFFSET+6]=BRUCE_LONE_MOVW_RETURN_BYTES
        b[BRUCE_LONE_MOVW_OFFSET+4]^=1
        with self.assertRaisesRegex(ValueError,"bytes mismatch"):
            classify_bruce_lone_movw(bytes(b))

    def test_source_sha_gate_before_results(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            audit(fixture(),"bruce_prod")

    def test_limits_fail_closed(self):
        b=fixture()
        for stop,window in [(-1,96),(len(b)+1,96),(256,2),(256,400)]:
            with self.subTest(stop=stop,window=window):
                with self.assertRaises(ValueError):
                    analyze_encodings(b,stop,pair_window=window)

    def test_32bit_mov_decode_rejects_invalid_offsets(self):
        for off in (-2,1,256):
            self.assertIsNone(decode_thumb_mov_imm(fixture(),off))
        self.assertIsNone(decode_thumb_mov_imm(bytearray(fixture()),0))


if __name__=="__main__":
    unittest.main()
