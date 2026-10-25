"""Synthetic Phase-28 regressions; no proprietary bootloader image is included."""
import hashlib
import struct
import unittest

from tools import audit_bucket_node_provenance as m


def encode_bl(site, target):
    delta=target-site-4
    if delta&1 or not -(1<<24)<=delta<(1<<24):
        raise ValueError("BL target out of range")
    bits=delta & ((1<<25)-1)
    s=(bits>>24)&1
    i1,i2=(bits>>23)&1,(bits>>22)&1
    j1,j2=1^(s^i1),1^(s^i2)
    return struct.pack("<HH",0xf000|(s<<10)|((bits>>12)&0x3ff),
                       0xd000|(j1<<13)|(j2<<11)|((bits>>1)&0x7ff))


def fixture():
    image=bytearray(b"\xff"*m.SIZE)
    for at,encoded in m.ANCHORS.items():
        raw=bytes.fromhex(encoded)
        image[at:at+len(raw)]=raw
    for at,val in m.LITERALS.items():
        struct.pack_into("<I",image,at,val)
    for site,dest in m.DIRECT_BL.items():
        image[site:site+4]=encode_bl(site,dest)
    return bytes(image)


def synthetic_ranges(image):
    return {name:(start,end,hashlib.sha256(image[start:end]).hexdigest())
            for name,(start,end,_) in m.REGIONS.items()}


def audited(image, fingerprints=None):
    return m.audit(image,expected_sha256=hashlib.sha256(image).hexdigest(),
                   fingerprints=synthetic_ranges(image) if fingerprints is None
                   else fingerprints)


class IndexedNodeProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture()

    def test_original_sha_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.image)

    def test_both_insertions_have_the_same_head_formula(self):
        r=audited(self.image)
        self.assertEqual(r["bucket_base"],"0x2000a7f8")
        self.assertEqual(r["bucket_stride_bytes"],20)
        self.assertEqual([x["callsite"] for x in r["insertion_sites"]],
                         ["0x60811a32","0x60811e0c"])

    def test_first_node_is_embedded_at_r6_plus_four(self):
        a=audited(self.image)["insertion_sites"][0]
        self.assertEqual(a["node_setup"],"0x608119fe")
        self.assertEqual(a["index_load"],"0x60811a14")
        self.assertIn("R6+4",a["node_source"])
        self.assertEqual(a["index_source"],"word [R6+0x2C]")

    def test_second_node_is_embedded_at_r4_plus_four(self):
        b=audited(self.image)["insertion_sites"][1]
        self.assertEqual(b["node_setup"],"0x60811dec")
        self.assertEqual(b["index_load"],"0x60811df6")
        self.assertIn("R4+4",b["node_source"])
        self.assertEqual(b["index_source"],"word [R4+0x2C]")

    def test_prior_pointer_chain_is_explicit(self):
        r=audited(self.image)["insertion_sites"]
        self.assertIn("[[R10]+0xC]+0xC",r[0]["node_source"])
        self.assertIn("[[incoming R0+0xC]+0xC]",r[1]["node_source"])

    def test_comparisons_are_after_indexed_insertions(self):
        r=audited(self.image)["insertion_sites"]
        self.assertTrue(all(int(x["comparison_after_call"].split()[0],16)>
                            int(x["callsite"],16) for x in r))
        self.assertTrue(all(x["guard_before_call_in_selected_window"]==
                            "NOT IDENTIFIED" for x in r))

    def test_no_unwarranted_bounds_claims(self):
        r=audited(self.image)
        self.assertEqual(r["facts"]["bucket_array_element_count"],"UNKNOWN")
        self.assertEqual(r["facts"]["caller_earlier_validation"],
                         "NOT EXHAUSTIVELY TRACED")
        self.assertEqual(r["critical_limits"]["out_of_bounds_memory_access"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["critical_limits"]["USB_input_controls_index"],
                         "NOT DEMONSTRATED")

    def test_known_call_targets_are_attested(self):
        self.assertEqual(len(m.DIRECT_BL),4)
        self.assertEqual(audited(self.image)["insertion_sites"][0]["callee"],
                         "0x608109b8")

    def test_changed_first_insertion_bl_rejected(self):
        image=bytearray(self.image)
        image[0x11a32:0x11a36]=encode_bl(0x11a32,0x109fe)
        with self.assertRaisesRegex(ValueError,"Direct BL target mismatch"):
            audited(bytes(image))

    def test_changed_second_insertion_bl_rejected(self):
        image=bytearray(self.image)
        image[0x11e0c:0x11e10]=encode_bl(0x11e0c,0x109fe)
        with self.assertRaisesRegex(ValueError,"Direct BL target mismatch"):
            audited(bytes(image))

    def test_mutated_node_provenance_instruction_rejected(self):
        image=bytearray(self.image)
        image[0x119fe]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            audited(bytes(image))

    def test_mutated_post_call_comparison_rejected(self):
        image=bytearray(self.image)
        image[0x11e18]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            audited(bytes(image))

    def test_literal_mutation_rejected(self):
        image=bytearray(self.image)
        struct.pack_into("<I",image,0x11e40,0x20009114)
        with self.assertRaisesRegex(ValueError,"Bucket literal mismatch"):
            audited(bytes(image))

    def test_unanchored_region_mutation_rejected(self):
        original_ranges=synthetic_ranges(self.image)
        image=bytearray(self.image)
        image[0x11e1e]^=1
        with self.assertRaisesRegex(ValueError,"Range SHA-256 mismatch"):
            audited(bytes(image),fingerprints=original_ranges)

    def test_bad_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            audited(self.image[:-1])

    def test_hypothetical_address_arithmetic_is_not_bounds_validation(self):
        self.assertEqual(m.hypothetical_head(0),m.BUCKET_BASE)
        self.assertEqual(m.hypothetical_head(1),m.BUCKET_BASE+20)
        with self.assertRaises(ValueError):
            m.hypothetical_head(-1)
        with self.assertRaises(ValueError):
            m.hypothetical_head(1<<32)

    def test_no_hardware_or_security_claim(self):
        r=audited(self.image)
        self.assertFalse(r["hardware_access"])
        self.assertFalse(r["usb_io"])
        self.assertFalse(r["flash_or_fuse_writes"])
        self.assertEqual(r["critical_limits"]["hab_closed_bypass"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["critical_limits"]["host_to_flash_write"],
                         "NOT DEMONSTRATED")


if __name__=="__main__":
    unittest.main()
