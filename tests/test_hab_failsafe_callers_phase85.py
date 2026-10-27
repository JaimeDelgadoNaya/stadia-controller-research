"""Synthetic tests for bounded, read-only HAB failsafe caller candidate census."""
import struct
import unittest

from tools.audit_hab_failsafe_callers_phase85 import (
    BRUCE_XIP_BASE, candidate_branch_prefix, enumerate_candidate_references,
    audit,
)


class HABFailsafeCallerTests(unittest.TestCase):
    def test_thumb16_branch_to_target_is_candidate_not_proven_caller(self):
        image=bytearray(b"\xff"*128)
        # B.n at offset 0x10: PC at 0x14, imm 9 halfwords -> 0x26.
        struct.pack_into("<H", image, 0x10, 0xe009)
        pointers, branches=enumerate_candidate_references(
            bytes(image), target=BRUCE_XIP_BASE+0x26
        )
        self.assertEqual(pointers, [])
        self.assertEqual(len(branches), 1)
        self.assertEqual(branches[0]["file_offset"], "0x10")
        self.assertEqual(branches[0]["destination"], "0x60040026")
        self.assertEqual(branches[0]["mnemonic"], "b")
        self.assertFalse(branches[0]["real_instruction_boundary_established"])
        self.assertFalse(branches[0]["reachable_in_hardware"])

    def test_thumb_pointer_candidates_are_not_live_callbacks(self):
        image=bytearray(b"\xff"*128)
        struct.pack_into("<I", image, 0x30, BRUCE_XIP_BASE+0x26)
        struct.pack_into("<I", image, 0x40, BRUCE_XIP_BASE+0x27)
        pointers, branches=enumerate_candidate_references(
            bytes(image), target=BRUCE_XIP_BASE+0x26
        )
        self.assertEqual(len(pointers), 2)
        self.assertTrue(all(not p["actual_reference_established"] for p in pointers))
        self.assertEqual([p["thumb_entry_bit"] for p in pointers],[False,True])
        self.assertEqual(branches, [])

    def test_pre_csf_boundary_excludes_trailing_raw_pointers(self):
        image=bytearray(b"\xff"*128)
        struct.pack_into("<I", image, 0x70, BRUCE_XIP_BASE+0x26)
        a,_=enumerate_candidate_references(bytes(image),stop=0x70,
                                           target=BRUCE_XIP_BASE+0x26)
        b,_=enumerate_candidate_references(bytes(image),stop=128,
                                           target=BRUCE_XIP_BASE+0x26)
        self.assertEqual(len(a),0)
        self.assertEqual(len(b),1)

    def test_unknown_direct_caller_is_not_equivalent_to_no_call(self):
        data=b"\xff"*128
        pointers,branches=enumerate_candidate_references(
            data,target=BRUCE_XIP_BASE+0x26
        )
        self.assertEqual((pointers,branches),([],[]))

    def test_reject_unknown_target_and_bad_data(self):
        for sample,base,target,stop in [
            (b"\xff"*10,BRUCE_XIP_BASE,BRUCE_XIP_BASE+0x20,None),
            (b"\xff"*10,BRUCE_XIP_BASE,BRUCE_XIP_BASE+3,None),
            (b"\xff"*10,BRUCE_XIP_BASE,BRUCE_XIP_BASE,-1),
            (b"\xff"*10,BRUCE_XIP_BASE,BRUCE_XIP_BASE,11),
            (bytearray(b"\xff"*64),BRUCE_XIP_BASE,BRUCE_XIP_BASE,64),
        ]:
            with self.subTest(target=target,stop=stop):
                with self.assertRaises(ValueError):
                    enumerate_candidate_references(sample,base=base,target=target,stop=stop)

    def test_branch_prefix_gate_includes_b_n_and_bl_w(self):
        self.assertTrue(candidate_branch_prefix(0xe009))
        self.assertTrue(candidate_branch_prefix(0xf000))
        self.assertFalse(candidate_branch_prefix(0x6801))

    def test_original_hash_enforced_before_analysis(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            audit(bytes(1050984))


if __name__=="__main__":
    unittest.main()
