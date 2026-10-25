"""Phase-29 synthetic regression tests, without OEM firmware or hardware access."""
import hashlib
import struct
import unittest

from tools import audit_bucket_index_writers as m


def fixture():
    image=bytearray(b"\xff"*m.SIZE)
    for off,encoding in m.ANCHORS.items():
        raw=bytes.fromhex(encoding)
        image[off:off+len(raw)]=raw
    for off,value in m.LITERALS.items():
        struct.pack_into("<I",image,off,value)
    return bytes(image)


def fingerprints_for(image):
    return {name:(start,end,hashlib.sha256(image[start:end]).hexdigest())
            for name,(start,end,_) in m.REGIONS.items()}


def audited(image, fingerprints=None):
    return m.audit(image, expected_sha256=hashlib.sha256(image).hexdigest(),
                   fingerprints=fingerprints if fingerprints is not None
                   else fingerprints_for(image))


class BucketIndexWritersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake=fixture()

    def test_production_digest_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.fake)

    def test_local_store_census_identifies_exact_five_locations(self):
        result=audited(self.fake)
        self.assertEqual(len(result["selected_word_store_candidates"]),5)
        self.assertEqual(
            [x["address"] for x in result["selected_word_store_candidates"]],
            ["0x608115a0","0x60811f90","0x60811fb2",
             "0x60812056","0x608120d6"])

    def test_source_classifications_include_runtime_reassignments(self):
        result=audited(self.fake)
        sources=[x["source"] for x in result["source_evidence"]]
        self.assertIn("R3=[R4+0x50] (object's stored reference index)",sources)
        self.assertTrue(any("max_unsigned" in x for x in sources))
        self.assertEqual(result["initializer"]["conditional_unsigned_range"],[0,15])

    def test_constructor_caps_unsigned_argument_at_15(self):
        values=[(0,0),(1,1),(14,14),(15,15),(16,15),(31,15),
                (0x7fffffff,15),(0xffffffff,15)]
        for raw,expected in values:
            with self.subTest(raw=raw):
                self.assertEqual(m.clamp_initial_index_unsigned(raw),expected)

    def test_unsigned_max_does_not_establish_upper_bound(self):
        self.assertEqual(m.pick_unsigned_max(2,15),15)
        self.assertEqual(m.pick_unsigned_max(20,15),20)
        self.assertEqual(m.pick_unsigned_max(0xffffffff,0),0xffffffff)

    def test_not_a_global_bounds_proof(self):
        limits=audited(self.fake)["limits"]
        self.assertTrue(limits["local_constructor_cap_not_global_invariant"])
        self.assertEqual(limits["size_of_indexed_bucket_array"],"UNKNOWN")
        self.assertEqual(limits["runtime_index_domain"],"UNKNOWN")
        self.assertEqual(limits["out_of_bounds_index"],"NOT DEMONSTRATED")

    def test_no_exploit_or_host_reachability_claim(self):
        r=audited(self.fake)
        self.assertFalse(r["device_access"])
        self.assertFalse(r["usb_transactions"])
        self.assertEqual(r["limits"]["USB_host_control"],"NOT DEMONSTRATED")
        self.assertEqual(r["limits"]["HAB_closed_bypass"],"NOT DEMONSTRATED")

    def test_changed_store_instruction_rejected(self):
        image=bytearray(self.fake)
        image[0x11fb2]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            audited(bytes(image))

    def test_wrong_constructor_predicate_rejected(self):
        image=bytearray(self.fake)
        image[0x1159c]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            audited(bytes(image))

    def test_unexpected_extra_store_site_detected(self):
        image=bytearray(self.fake)
        struct.pack_into("<H",image,0x12190,0x62c0)
        with self.assertRaisesRegex(ValueError,"candidate census changed"):
            audited(bytes(image))

    def test_wrong_runtime_literal_rejected(self):
        image=bytearray(self.fake)
        struct.pack_into("<I",image,0x11fe0,0x20009114)
        with self.assertRaisesRegex(ValueError,"Literal mismatch"):
            audited(bytes(image))

    def test_region_fingerprint_detects_unanchored_change(self):
        ref=fingerprints_for(self.fake)
        image=bytearray(self.fake)
        image[0x11560]^=1
        with self.assertRaisesRegex(ValueError,"Region fingerprint mismatch"):
            audited(bytes(image),fingerprints=ref)

    def test_bad_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            audited(self.fake[:-1])

    def test_bad_scan_bounds_and_offsets(self):
        for kw in [{"displacement":45},
                   {"displacement":128},
                   {"start":0x11401,"end":0x12200}]:
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                m.scan_thumb16_word_stores(self.fake,**kw)

    def test_bad_unsigned_inputs_rejected(self):
        for val in (-1,1<<32,1.5,None):
            with self.subTest(val=val), self.assertRaises(ValueError):
                m.clamp_initial_index_unsigned(val)
        with self.assertRaises(ValueError):
            m.pick_unsigned_max(12,-2)

    def test_repeated_derived_sources_stay_conditional(self):
        r=audited(self.fake)
        self.assertEqual(r["runtime_field_sources"]["index_copies_from_another_object"],
                         ["0x60811f90","0x60811fb2"])
        self.assertEqual(r["runtime_field_sources"]["later_field_mutation_and_aliases"],
                         "NOT EXHAUSTIVELY RESOLVED")


if __name__=="__main__":
    unittest.main()
