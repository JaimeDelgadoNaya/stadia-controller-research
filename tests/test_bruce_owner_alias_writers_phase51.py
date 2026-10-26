"""Phase51: require exact PC-relative literal xrefs; reject unsafe alias leaps."""
import unittest
from tools import audit_bruce_owner_alias_writers_phase51 as p
def ins(pc,m,op):return {"pc":pc,"m":m,"op":op}

class Phase51OwnerAliasTests(unittest.TestCase):
    def test_pc_alignment_and_literal_target(self):
        self.assertEqual(p.pc_aligned_value(0x60071416,0x20),0x60071438)
        self.assertEqual(p.pc_aligned_value(0x60071418,0x1c),0x60071438)
        xs=[ins(0x60071416,"ldr","r0, [pc, #0x20]"),
            ins(0x6007141a,"mov","r4, r0")]
        self.assertEqual(len(p.xref_loads(xs,0x60071438)),1)
        self.assertEqual(len(p.xref_loads(xs,0x6007143c)),0)
    def test_base_plus_offset_store_candidate(self):
        xs=[
            ins(0x100,"ldr","r0, [pc, #0x10]"),
            ins(0x102,"mov","r4, r0"),
            ins(0x104,"mov","r1, r3"),
            ins(0x106,"str","r1, [r4, #4]"),
            ins(0x108,"strb","r2, [r4, #0xc]"),
            ins(0x10a,"bne","#0x210"),
            ins(0x10c,"str","r1, [r4, #8]")]
        result=p.local_field_actions(xs,0,"r0")
        self.assertEqual([q["field"] for q in result],["class_record_pointer","class_record_count"])
        self.assertFalse(any(q["field"]=="config_method" for q in result))
    def test_alias_killed_by_reassignment(self):
        xs=[ins(0x100,"ldr","r0, [pc, #0x10]"),
            ins(0x102,"mov","r4, r0"),
            ins(0x104,"ldr","r4, [r3]"),
            ins(0x106,"str","r1, [r4, #4]")]
        self.assertEqual(p.local_field_actions(xs,0,"r0"),[])
    def test_branch_terminates_local_proof(self):
        xs=[ins(0x100,"ldr","r0, [pc, #0x10]"),
            ins(0x102,"bl","#0x400"),
            ins(0x104,"str","r1, [r0, #4]")]
        self.assertEqual(p.local_field_actions(xs,0,"r0"),[])
    def test_exact_original_image_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.audit(b"synthetic")
if __name__=="__main__":unittest.main()
