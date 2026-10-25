"""Phase-21 synthetic tests; no proprietary bootloader or USB access."""
import hashlib
import json
import struct
import unittest
from pathlib import Path

from tools import audit_global_alias_sources as m


def fixture():
    image=bytearray(b"\xff"*m.SIZE)
    for at,enc in m.ANCHORS.items():
        raw=bytes.fromhex(enc)
        image[at:at+len(raw)]=raw
    for at in (0xC0BC,0x9E8C,0x9F84):
        struct.pack_into("<I",image,at,m.GLOBAL)
    return bytes(image)


def audited(data, strict_counts=False):
    return m.audit(data,expected_sha256=hashlib.sha256(data).hexdigest(),
                   strict_counts=strict_counts)


class GlobalAliasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture()

    def test_sha_lock_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.image)

    def test_alias_constructor_chain_resolved(self):
        r=audited(self.image)
        x=r["verified_conditional_alias_chain"]
        self.assertEqual(x["literal_at"],"0x6080c0bc")
        self.assertEqual(x["load_into_r0"],"0x6080c0b2")
        self.assertEqual(x["bl_target"],"0x6080bac0")
        self.assertEqual(len(x["constructor_stores"]),4)
        self.assertFalse(r["usb_transfers"])

    def test_three_independent_lit_sites(self):
        r=audited(self.image)
        self.assertEqual(r["global_pointer_sources"]["aligned_literal_words"],3)
        self.assertEqual(r["global_pointer_sources"]["pc_relative_load_candidates"],3)
        sites={c["at"] for c in r["global_pointer_sources"]["loads"]}
        self.assertEqual(sites,{"0x6080c0b2","0x60809e6a","0x60809eb8"})

    def test_two_usb_fields_stored_via_r4(self):
        stores=audited(self.image)["verified_conditional_alias_chain"]["constructor_stores"]
        values={x["name"]:x["ram_address"] for x in stores}
        self.assertEqual(values["bulk_out_handler"],"0x20009178")
        self.assertEqual(values["bulk_in_handler"],"0x20009170")
        self.assertTrue(all("r4" in x["base_register"] for x in stores))

    def test_thumb_bl_immediate_computes_expected_target(self):
        self.assertEqual(m.decode_bl(self.image,0xC0B4),0x6080BAC0)

    def test_thumb_bl_rejects_non_bl(self):
        with self.assertRaisesRegex(ValueError,"Thumb BL"):
            m.decode_bl(self.image,0xBB50)

    def test_thumb32_positive_literal_candidate(self):
        data=bytearray(self.image)
        struct.pack_into("<HH",data,0x1100,0xF8DF,0x0008)
        struct.pack_into("<I",data,0x110C,m.GLOBAL)
        items=m.literal_load_candidates(data,m.literal_words(data))
        self.assertTrue(any(x["at"]=="0x60801100" and
                            x["literal"]=="0x6080110c" and
                            x["kind"].startswith("Thumb32") for x in items))

    def test_thumb32_negative_literal_candidate(self):
        data=bytearray(self.image)
        struct.pack_into("<I",data,0x111C,m.GLOBAL)
        struct.pack_into("<HH",data,0x1120,0xF85F,0x1008)
        items=m.literal_load_candidates(data,m.literal_words(data))
        self.assertTrue(any(x["at"]=="0x60801120" and
                            x["literal"]=="0x6080111c" and
                            x["register"]=="r1" for x in items))

    def test_misaligned_pointer_not_counted(self):
        data=bytearray(self.image)
        struct.pack_into("<I",data,0x1171,m.GLOBAL)
        self.assertNotIn(0x1171,m.literal_words(data))

    def test_invalid_candidate_scan_bounds(self):
        for bounds in ((0x1001,0x1200),(0x1100,0x1101),(-2,0x1200),
                       (0x1200,0x1100)):
            with self.subTest(bounds=bounds),self.assertRaises(ValueError):
                m.literal_load_candidates(self.image,set(),*bounds)

    def test_constructor_anchor_mutation_rejected(self):
        changed=bytearray(self.image)
        changed[0xC0B4]^=1
        with self.assertRaisesRegex(ValueError,"anchor"):
            audited(bytes(changed))

    def test_literal_mutation_rejected(self):
        changed=bytearray(self.image)
        struct.pack_into("<I",changed,0xC0BC,0)
        with self.assertRaisesRegex(ValueError,"Constructor literal"):
            audited(bytes(changed))

    def test_strict_counts_refuses_partial_fixture(self):
        with self.assertRaisesRegex(ValueError,"census drifted"):
            audited(self.image,strict_counts=True)

    def test_wrong_size_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            audited(self.image[:-1])

    def test_scope_and_security_claims_remain_limited(self):
        r=audited(self.image)
        self.assertEqual(r["other_aliases"],"NOT FULLY RESOLVED")
        self.assertEqual(r["host_to_flash_write"],"NOT DEMONSTRATED")
        self.assertEqual(r["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(r["custom_execution"],"NOT DEMONSTRATED")
        self.assertFalse(r["hardware_access"])

if __name__=="__main__":
    unittest.main()
