"""Synthetic regression tests for phase 23 direct-call alias handoffs.

No proprietary firmware is included or read by these tests.
"""
import hashlib
import struct
import unittest

from tools import audit_interprocedural_aliases as m


CALL_ENCODINGS = {
    0xC0B4:"fff704fd",
    0x2504:"08f088fe",
    0x8138:"03f06ef8",
    0xFB4C:"fbf716fb",
    0xB186:"fff703fc",
    0xB18E:"f7f787f8",
    0xB196:"fef7b9fb",
    0xB19E:"fef7fbfd",
    0x9AC2:"fff7e1fd",
}

def fixture():
    data=bytearray(b"\xff"*m.SIZE)
    for off, enc in m.ANCHORS.items():
        data[off:off+len(enc)//2]=bytes.fromhex(enc)
    for off, enc in CALL_ENCODINGS.items():
        data[off:off+len(enc)//2]=bytes.fromhex(enc)
    for _, load, _, literal, _ in m.WRAPPERS:
        pc=(m.BASE+load+4)&~3
        imm=(m.BASE+literal-pc)//4
        assert 0 <= imm <= 255
        data[load:load+2]=struct.pack("<H",0x4800|imm)
        struct.pack_into("<I",data,literal,m.GLOBAL)
    return bytes(data)


def tested(image):
    return m.audit(image, expected_sha256=hashlib.sha256(image).hexdigest())


class InterproceduralAliasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture()

    def test_unknown_sha_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.image)

    def test_four_verified_global_wrapper_handoffs(self):
        r=tested(self.image)
        edges=r["bounded_direct_global_handoffs"]
        self.assertEqual(len(edges),4)
        self.assertEqual({x["target"] for x in edges},
                         {"0x6080bac0","0x6080b218","0x6080b17c"})
        self.assertTrue(all(x["argument_r0"]=="0x20008b78" for x in edges))
        self.assertFalse(r["hardware_access"])

    def test_subsystem_subobject_offsets_and_call_targets(self):
        r=tested(self.image)
        edges=r["subsystem_initializer"]["derived_argument_calls"]
        self.assertEqual([x["global_offset"] for x in edges],
                         ["0x568","0x560","0x630","0x578"])
        self.assertEqual([x["target"] for x in edges],
                         ["0x6080a990","0x608022a0","0x6080990c","0x60809d98"])
        self.assertTrue(all(not x["callee_body_checked"] for x in edges))

    def test_controller_service_one_hop_tail(self):
        r=tested(self.image)["controller_service"]
        self.assertEqual(r["derived_argument_r0"],"0x200091a8")
        self.assertEqual(r["tail_branch_target"],"0x60809abc")
        self.assertEqual(r["next_derived_argument_r0"],"0x200091bc")
        self.assertEqual(r["first_tail_callee"],"0x60809688")

    def test_neither_subobject_equals_direct_callback_fields(self):
        r=tested(self.image)
        args={e["argument_r0"] for e in r["subsystem_initializer"]["derived_argument_calls"]}
        self.assertNotIn("0x20009170",args)
        self.assertNotIn("0x20009178",args)
        self.assertEqual(r["interprocedural_callback_replacement"],
                         "NOT PROVEN OR EXCLUDED")

    def test_literal_value_mutation_rejected(self):
        image=bytearray(self.image)
        struct.pack_into("<I",image,0xFB60,0)
        with self.assertRaisesRegex(ValueError,"Unexpected global pointer input"):
            tested(bytes(image))

    def test_literal_load_encoding_rejected(self):
        image=bytearray(self.image)
        image[0x2503]=0x49
        with self.assertRaisesRegex(ValueError,"PC-relative load into R0"):
            tested(bytes(image))

    def test_wrapper_call_mutation_rejected(self):
        image=bytearray(self.image)
        image[0x8138]^=1
        with self.assertRaisesRegex(ValueError,"Changed direct call edge"):
            tested(bytes(image))

    def test_subobject_call_mutation_rejected(self):
        image=bytearray(self.image)
        image[0xB196]^=1
        with self.assertRaisesRegex(ValueError,"Changed subobject BL edge"):
            tested(bytes(image))

    def test_tail_branch_mutation_rejected(self):
        image=bytearray(self.image)
        image[0xB21C+2]^=1
        with self.assertRaisesRegex(ValueError,"Machine-code anchor"):
            tested(bytes(image))

    def test_tail_callee_change_rejected(self):
        image=bytearray(self.image)
        image[0x9AC2]^=1
        with self.assertRaisesRegex(ValueError,"Changed first tail"):
            tested(bytes(image))

    def test_subobject_add_instruction_change_rejected(self):
        image=bytearray(self.image)
        image[0xB192]^=1
        with self.assertRaisesRegex(ValueError,"Machine-code anchor"):
            tested(bytes(image))

    def test_unrelated_instruction_rejected_by_decoder(self):
        with self.assertRaisesRegex(ValueError,"Not a Thumb jump"):
            m.decode_thumb_jump(self.image,0xB17E)

    def test_decoder_rejects_invalid_location(self):
        with self.assertRaisesRegex(ValueError,"Invalid Thumb jump offset"):
            m.decode_thumb_jump(self.image,1)

    def test_wrong_image_size_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            tested(self.image[:-1])

    def test_limits_on_claims_remain_visible(self):
        r=tested(self.image)
        self.assertEqual(r["host_to_flash_writer"],"NOT DEMONSTRATED")
        self.assertEqual(r["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(r["custom_firmware_execution"],"NOT DEMONSTRATED")
        self.assertFalse(r["usb_transactions"])

if __name__=="__main__":
    unittest.main()
