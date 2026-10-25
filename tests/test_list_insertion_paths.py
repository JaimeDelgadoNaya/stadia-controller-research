"""Phase-27 synthetic list-insertion regression tests; no proprietary firmware."""
import hashlib
import struct
import unittest

from tools import audit_list_insertion_paths as m


def encode_bl(site, target):
    """Encode a Thumb-2 BL for testing the known direct-call inventory."""
    offset=target-site-4
    if (offset&1) or not -(1<<24)<=offset<(1<<24):
        raise ValueError("Invalid synthetic Thumb BL offset")
    bits=offset & ((1<<25)-1)
    s,i1,i2=(bits>>24)&1,(bits>>23)&1,(bits>>22)&1
    j1,j2=1^(i1^s),1^(i2^s)
    h1=0xf000|(s<<10)|((bits>>12)&0x3ff)
    h2=0xd000|(j1<<13)|(j2<<11)|((bits>>1)&0x7ff)
    return struct.pack("<HH",h1,h2)


def fixture():
    image=bytearray(b"\xff"*m.SIZE)
    for site,hexbytes in m.ANCHORS.items():
        raw=bytes.fromhex(hexbytes)
        image[site:site+len(raw)]=raw
    for site,target in m.BUCKET_LITERALS.items():
        struct.pack_into("<I",image,site,target)
    for site in m.FRONT_SITES:
        image[site:site+4]=encode_bl(site,0x109B8)
    for site in m.ORDERED_SITES:
        image[site:site+4]=encode_bl(site,0x109D0)
    # Anchored T4 B.W from the source image, no firmware included.
    image[m.ORDERED_TAIL_SITE:m.ORDERED_TAIL_SITE+4]=bytes.fromhex("fff769b9")
    return bytes(image)


def synthetic_regions(image):
    return {name:(start,end,hashlib.sha256(image[start:end]).hexdigest())
            for name,(start,end,_) in m.REGIONS.items()}


def tested(image, regions=None):
    return m.audit(image,expected_sha256=hashlib.sha256(image).hexdigest(),
                   fingerprints=synthetic_regions(image) if regions is None else regions)


class ListInsertionPathsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture()

    def test_production_sha_refuses_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.image)

    def test_front_insertion_direct_calls(self):
        r=tested(self.image)
        self.assertEqual(r["list_insertion"]["front_direct_bl_sites"],9)
        self.assertEqual(
            sum(x["operation"]=="front_insert" for x in
                r["list_insertion"]["verified_static_edges"]),9)

    def test_ordered_insertion_direct_calls_and_tail_branch(self):
        r=tested(self.image)["list_insertion"]
        self.assertEqual(r["ordered_direct_bl_sites"],4)
        self.assertEqual(r["ordered_direct_tail_branches"],1)
        tail=next(x for x in r["verified_static_edges"]
                  if x["operation"]=="ordered_insert_tail")
        self.assertEqual(tail["site"],"0x608116fa")
        self.assertEqual(tail["branch_kind"],"B.W")
        self.assertEqual(tail["target"],"0x608109d0")

    def test_list_insertion_updates_two_links_and_counter(self):
        r=tested(self.image)["list_insertion"]["front_semantics"]
        self.assertEqual(r["node_argument"],"r1; runtime address depends on caller")
        self.assertIn("node+16=head",r["writes"])
        self.assertIn("head+0=count+1",r["writes"])

    def test_indexed_bucket_examples(self):
        values=tested(self.image)["indexed_bucket_examples"]
        self.assertEqual([x["callsite"] for x in values],
                         ["0x60811a32","0x60811e0c"])
        self.assertTrue(all("0x2000a7f8+20*index" in x["formula"]
                            for x in values))

    def test_indexed_base_differs_from_phase26_list_heads(self):
        c=tested(self.image)["comparison_with_phase26_heads"]
        self.assertEqual(c["indexed_bucket_base"],"0x2000a7f8")
        self.assertTrue(c["different_ram_region_at_known_base"])
        self.assertTrue(c["cannot_equate_all_callers_to_phase26_heads"])

    def test_one_constructor_store_for_each_known_pointer_field(self):
        c=tested(self.image)["known_pointer_field_write_search"]
        self.assertEqual([x["at"] for x in c["raw_positive_immediate_STRW_candidates"]["0x560"]],
                         ["0x6080baec"])
        self.assertEqual([x["at"] for x in c["raw_positive_immediate_STRW_candidates"]["0x568"]],
                         ["0x6080baf2"])
        self.assertEqual(c["later_reassignment"],"NOT PROVEN OR EXCLUDED")

    def test_extra_strw_encoding_is_detected(self):
        img=bytearray(self.image)
        struct.pack_into("<HH",img,0x1100,0xf8c1,0x6560)
        with self.assertRaisesRegex(ValueError,"immediate-STR.W census changed"):
            tested(bytes(img))

    def test_edited_front_direct_call_rejected(self):
        img=bytearray(self.image)
        img[0x11808:0x1180c]=encode_bl(0x11808,0x109D0)
        with self.assertRaisesRegex(ValueError,"Branch edge mismatch"):
            tested(bytes(img))

    def test_edited_ordered_direct_call_rejected(self):
        img=bytearray(self.image)
        img[0x11706:0x1170a]=encode_bl(0x11706,0x109B8)
        with self.assertRaisesRegex(ValueError,"Branch edge mismatch"):
            tested(bytes(img))

    def test_tail_branch_encoding_cannot_be_bl(self):
        img=bytearray(self.image)
        img[0x116fa:0x116fe]=encode_bl(0x116fa,0x109D0)
        with self.assertRaisesRegex(ValueError,"Branch edge mismatch"):
            tested(bytes(img))

    def test_anchor_change_rejected(self):
        img=bytearray(self.image)
        img[0x109ca]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            tested(bytes(img))

    def test_bucket_base_mutation_rejected(self):
        img=bytearray(self.image)
        struct.pack_into("<I",img,0x11e40,0x20009114)
        with self.assertRaisesRegex(ValueError,"Indexed bucket literal mismatch"):
            tested(bytes(img))

    def test_fingerprint_detects_unanchored_mutation(self):
        original=synthetic_regions(self.image)
        img=bytearray(self.image)
        img[0x109c6]^=1
        with self.assertRaisesRegex(ValueError,"Code region fingerprint mismatch"):
            tested(bytes(img),regions=original)

    def test_bad_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            tested(self.image[:-1])

    def test_no_claim_of_exploit_or_host_path(self):
        r=tested(self.image)
        self.assertFalse(r["usb_transactions"])
        self.assertFalse(r["hardware_access"])
        self.assertEqual(r["conclusions"]["host_to_list_insertion"],"NOT DEMONSTRATED")
        self.assertEqual(r["conclusions"]["host_usb_to_flash_writer"],"NOT DEMONSTRATED")
        self.assertEqual(r["conclusions"]["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(r["conclusions"]["callback_field_overlap"],"NOT DEMONSTRATED")


if __name__=="__main__":
    unittest.main()
