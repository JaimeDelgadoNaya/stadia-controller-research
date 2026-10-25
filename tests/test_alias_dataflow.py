"""Phase 22 synthetic bounded Thumb alias tests (no proprietary image)."""
import hashlib
import struct
import unittest
from tools import audit_alias_dataflow as m


def base_image():
    return bytearray(b"\xff" * m.SIZE)


def emit(code, location=0x1100, literal_at=0x110C):
    data=base_image()
    raw = bytes.fromhex(code)
    data[location:location+len(raw)] = raw
    struct.pack_into("<I",data,literal_at,m.GLOBAL)
    return bytes(data)


def traced(hexcode, reg_name, location=0x1100):
    code=emit(hexcode,location)
    decoder=m._decoder()
    first=next(decoder.disasm(code[location:location+4],m.BASE+location,count=1))
    assert decoder.reg_name(first.operands[0].reg)==reg_name
    return m.trace_prefix(code,location,first.operands[0].reg)


class AliasDataflowTests(unittest.TestCase):
    def test_store_to_bulk_out_via_global_pointer(self):
        # LDR r4,[PC,#8]; STR.W r3,[r4,#0x600]; BX LR
        x=traced("024cc4f800367047","r4")
        self.assertEqual(len(x["writes"]),1)
        self.assertEqual(x["writes"][0]["ram"],"0x20009178")
        self.assertEqual(x["writes"][0]["field"],"bulk_OUT_handler")
        self.assertEqual(x["stopped_at"],"branch_or_return_boundary")

    def test_store_to_state_not_callback(self):
        # LDR r2,[PC,#8]; STRB.W r3,[r2,#0x6c4]; BX LR
        x=traced("024a82f8c4367047","r2")
        self.assertEqual(len(x["writes"]),1)
        self.assertEqual(x["writes"][0]["ram"],"0x2000923c")
        self.assertEqual(x["writes"][0]["field"],"other_field")

    def test_read_event_callback_pointer_not_store(self):
        # LDR r0, [PC,#8]; LDR.W r3,[r0,#0x5f0]; BX LR
        x=traced("0248d0f8f0357047","r0")
        self.assertEqual(len(x["reads"]),1)
        self.assertEqual(len(x["writes"]),0)
        self.assertEqual(x["reads"][0]["ram"],"0x20009168")

    def test_register_copy_preserves_global_alias(self):
        # LDR r0,[PC,#8]; MOV r4,r0; STR.W r3,[r4,#0x600]; BX LR
        x=traced("02480446c4f800367047","r0")
        self.assertEqual(x["writes"][0]["field"],"bulk_OUT_handler")

    def test_add_then_relative_store_reaches_callback(self):
        # LDR r0; ADD.W r0,r0,#0x5e8; STR.W r3,[r0,#0x18]; BX LR
        x=traced("024800f5bd60c0f818307047","r0")
        self.assertEqual(x["writes"][0]["field"],"bulk_OUT_handler")
        self.assertEqual(x["writes"][0]["offset_from_global"],"0x00000600")

    def test_branch_boundary_prevents_false_store_claim(self):
        # LDR r4; B +0; STR.W r3,[r4,#0x600] (not followed)
        x=traced("024c00e0c4f800367047","r4")
        self.assertEqual(x["writes"],[])
        self.assertEqual(x["stopped_at"],"branch_or_return_boundary")

    def test_call_boundary_does_not_enter_unverified_callee(self):
        # LDR r0; BL (relocation-free sample bytes); STR.W [r0,#0x600]
        x=traced("0248fff704fdc0f800367047","r0")
        self.assertEqual(x["writes"],[])
        self.assertEqual(x["stopped_at"],"call_boundary")
        self.assertEqual(x["call_boundaries"][0]["known_argument_aliases"],
                         {"r0":"0x20008b78"})
        self.assertFalse(x["call_boundaries"][0]["callee_followed"])

    def test_unrelated_call_does_not_claim_pointer_as_argument(self):
        x=traced("024cfff704fdc4f800367047","r4")
        self.assertEqual(x["call_boundaries"][0]["known_argument_aliases"],{})

    def test_initial_register_kill_stops_false_positive(self):
        # LDR r4; MOVS r4,#0; STR.W [r4,#0x600]
        x=traced("024c0024c4f800367047","r4")
        self.assertEqual(x["writes"],[])

    def test_invalid_halfword_address_or_limits(self):
        data=emit("024c7047")
        for at,lim in [(0x1101,96),(m.SIZE,96),(0x1100,3),(0x1100,300)]:
            with self.subTest(at=at,limit=lim),self.assertRaises(ValueError):
                m.trace_prefix(data,at,1,lim)

    def test_unsigned_signed_image_required(self):
        fake=emit("024c7047")
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(fake)

    def test_bad_image_size_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            m.audit(b"\xff"*(m.SIZE-1))

    def test_stop_and_unresolved_statuses_are_not_claimed_as_proof(self):
        x=traced("024cc4f800367047","r4")
        self.assertEqual(x["writes"][0]["code_reachable_from_host"],"NOT ESTABLISHED")
        self.assertIn("no alternate branch",x["scope"])

    def test_decoder_exists_in_pinned_capstone(self):
        decoder=m._decoder()
        ins=list(decoder.disasm(bytes.fromhex("7047"),m.BASE+0x1100))
        self.assertEqual(ins[0].mnemonic,"bx")


if __name__=="__main__":
    unittest.main()
