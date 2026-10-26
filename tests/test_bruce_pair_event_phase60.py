"""Phase 60 conservative alias and event xref regression tests."""
import struct
import unittest
from tools import audit_bruce_pair_event_phase60 as a


class Phase60SignedPairEvent(unittest.TestCase):
    def test_global_pair_bounds(self):
        self.assertEqual((a.PAIR_FIRST-a.PAIR_BASE,a.PAIR_SECOND-a.PAIR_BASE),
                         (0x37C,0x380))
        self.assertNotEqual(a.REAL_HANDLER_XIP,a.ITCM_TRAMPOLINE)

    def test_register_memory_and_arithmetic_patterns(self):
        m=a.MEM_RE.search("r2, [r3, #0x37c]")
        self.assertEqual((m.group(1),int(m.group("imm"),0)),("r3",0x37C))
        x=a.MOVE_RE.fullmatch("r4, r0")
        self.assertEqual(x.groups(),("r4","r0"))
        q=a.ARITH_RE.fullmatch("r3, r4, #0x37c")
        self.assertEqual(q.groups(),("r3","r4","0x37c"))
        self.assertIsNone(a.MEM_RE.search("r2, [r3, r0]"))

    def _signed_store_shaped_sample(self,branch=False):
        # Synthetic *code shape* only; never accepted by the SHA gate.
        # Use original layout of 16-bit LDR PC, 16-bit LDR SP, two
        # STR.W (T3) and LDR SP. Literal at image offset 0x23888.
        raw=bytearray(0x24000)
        off=0x23874
        seq=bytes.fromhex("044b 009a c3f8 7c23 019a c3f8 8023 00bf")
        raw[off:off+len(seq)]=seq
        if branch:
            # Explicit branch before first store; must stop analysis.
            raw[off+2:off+4]=bytes.fromhex("00e0")
        struct.pack_into("<I",raw,0x23888,a.PAIR_BASE)
        return raw

    def test_synthetic_writer_alias_read_vs_write(self):
        raw=self._signed_store_shaped_sample()
        seed={"pc":"0x60063874","loaded_register":"r3",
              "loaded_value":hex(a.PAIR_BASE),"execution_domain":"XIP"}
        result=a.run_local_alias(raw,seed,span=0x20)
        accesses=result["bounded_alias_pair_accesses"]
        self.assertEqual([(x["absolute_address"],x["read"]) for x in accesses],
                         [(hex(a.PAIR_FIRST),False),(hex(a.PAIR_SECOND),False)])

    def test_branch_blocks_unwarranted_alias_proof(self):
        raw=self._signed_store_shaped_sample(branch=True)
        seed={"pc":"0x60063874","loaded_register":"r3",
              "loaded_value":hex(a.PAIR_BASE),"execution_domain":"XIP"}
        self.assertEqual(a.run_local_alias(raw,seed,span=0x30)
                         ["bounded_alias_pair_accesses"],[])

    def test_known_thumb_handler_literal_only(self):
        raw=bytearray(0x40)
        struct.pack_into("<I",raw,0x20,a.REAL_HANDLER_XIP|1)
        struct.pack_into("<I",raw,0x24,a.ITCM_WRAPPER|1)
        refs=a.scan_target_pointer_literals(raw)
        self.assertEqual([x["file_offset"] for x in refs],["0x20","0x24"])

    def test_original_signed_sha_gate(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic unsigned")


if __name__=="__main__":
    unittest.main()
