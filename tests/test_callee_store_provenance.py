"""Synthetic tests for phase-24 pointer provenance; no OEM binary is included."""
import hashlib
import unittest

from tools import audit_callee_store_provenance as m


def image_with(start, code, extra=()):
    image=bytearray(b"\xff"*m.SIZE)
    image[start:start+len(code)]=code
    for offset, data in extra:
        image[offset:offset+len(data)]=data
    return bytes(image)


class CalleeStoreProvenanceTests(unittest.TestCase):
    def test_direct_store_uses_register_copy_and_base_offset(self):
        # MOV r5,r0; STR r0,[r5,#0xC]
        image=image_with(0x1000,bytes.fromhex("0546e860"))
        r=m.scan_range(image,"synthetic",0x1000,0x1004,{"r0":0x568})
        self.assertEqual(len(r["stores_via_known_alias"]),1)
        s=r["stores_via_known_alias"][0]
        self.assertEqual(s["global_offsets_written"],[0x574])
        self.assertEqual(s["ram_addresses"],["0x20008bec"])
        self.assertEqual(s["callback_fields_overlapped"],[])

    def test_direct_callback_store_is_detected(self):
        # STR r3,[r0]; incoming R0 points exactly at the IN handler field.
        image=image_with(0x1000,bytes.fromhex("0360"))
        r=m.scan_range(image,"synthetic",0x1000,0x1002,{"r0":0x5F8})
        self.assertEqual(r["stores_via_known_alias"][0]["callback_fields_overlapped"],
                         ["bulk_in_handler"])

    def test_subword_overlap_is_classified(self):
        self.assertEqual(m.callback_fields_overlapped(0x5F9,1),["bulk_in_handler"])
        self.assertEqual(m.callback_fields_overlapped(0x5FF,2),
                         ["bulk_in_handler","bulk_out_handler"])
        self.assertEqual(m.callback_fields_overlapped(0x600,4),["bulk_out_handler"])
        self.assertEqual(m.callback_fields_overlapped(0x5D8,4),[])

    def test_loaded_field_value_is_not_mistaken_for_same_pointer(self):
        # LDR r0,[r0]; STR r3,[r0] — second store uses a loaded value, not the base alias.
        image=image_with(0x1000,bytes.fromhex("00680360"))
        r=m.scan_range(image,"synthetic",0x1000,0x1004,{"r0":0x568})
        self.assertEqual(r["stores_via_known_alias"],[])
        self.assertTrue(any(x["kind"]=="store_through_field_derived_pointer"
                            for x in r["dynamic_pointer_accesses"]))
        self.assertEqual(r["dynamic_pointer_accesses"][0]["pointer_provenance"]
                         ["root_global_field_offset"],0x568)

    def test_known_pointer_handoff_is_recorded_at_call(self):
        # MOV r0,r4; BL 0x608021B4. Encoding is from the verified callsite.
        image=image_with(0x22AC,bytes.fromhex("2046fff781ff"))
        r=m.scan_range(image,"synthetic",0x22AC,0x22B2,{"r4":0x560})
        call=next(c for c in r["field_derived_call_handoffs"]
                  if c["at"]=="0x608022ae")
        self.assertEqual(call["target"],"0x608021b4")
        self.assertEqual(call["argument_provenance"]["r0"]["global_offset"],0x560)

    def test_caller_saved_clobber_preserves_r4_alias(self):
        # MOV r4,r0; ADDS r0,#0x14; BL 0x60810210; MOVS r3,#1; STRB r3,[r4,#0x10]
        code=bytes.fromhex("0446143006f037fa01232374")
        image=image_with(0x9D98,code)
        r=m.scan_range(image,"synthetic",0x9D98,0x9D98+len(code),{"r0":0x578})
        call=next(c for c in r["field_derived_call_handoffs"]
                  if c["at"]=="0x60809d9e")
        self.assertEqual(call["argument_provenance"]["r0"]["global_offset"],0x58C)
        self.assertEqual(r["stores_via_known_alias"][0]["global_offsets_written"],[0x588])

    def test_load_from_global_field_records_read_and_field_origin(self):
        # LDR r0,[r0] from the object field +0x568, followed by BL 0x60809048.
        code=bytes.fromhex("0068fef745fb")
        image=image_with(0xA9B8,code)
        r=m.scan_range(image,"synthetic",0xA9B8,0xA9B8+len(code),{"r0":0x568})
        self.assertEqual(r["reads_via_known_alias"][0]["global_offsets_read"],[0x568])
        call=next(c for c in r["field_derived_call_handoffs"]
                  if c["at"]=="0x6080a9ba")
        self.assertEqual(call["target"],"0x60809048")
        self.assertEqual(call["argument_provenance"]["r0"]["root_global_field_offset"],0x568)

    def test_pc_relative_literal_can_restore_known_global_alias(self):
        # LDR r4,[PC,#0x30] at 0x60802176 -> literal 0x608021A8 containing GLOBAL.
        image=image_with(0x2176,bytes.fromhex("0c4c"),((0x21A8,m.GLOBAL.to_bytes(4,"little")),))
        r=m.scan_range(image,"synthetic",0x2176,0x2178,{"r0":0x560})
        self.assertEqual(r["pc_relative_literals"][0]["value"],"0x20008b78")
        self.assertEqual(r["pc_relative_literals"][0]["literal_address"],"0x608021a8")

    def test_unrelated_literal_does_not_become_global_alias(self):
        image=image_with(0x2176,bytes.fromhex("0c4c"),((0x21A8,(0x20009DC0).to_bytes(4,"little")),))
        r=m.scan_range(image,"synthetic",0x2176,0x2178,{"r0":0x560})
        self.assertEqual(r["pc_relative_literals"][0]["value"],"0x20009dc0")
        self.assertEqual(r["reads_via_known_alias"],[])

    def test_dynamic_pointer_dereference_is_kept_unresolved(self):
        # LDR r3,[r0,#0xC]; LDR r4,[r3,#0xC]
        image=image_with(0x1000,bytes.fromhex("c3685c68"))
        r=m.scan_range(image,"synthetic",0x1000,0x1004,{"r0":0x59C})
        self.assertEqual(r["reads_via_known_alias"][0]["global_offsets_read"],[0x5A8])
        self.assertEqual(r["dynamic_pointer_accesses"][0]["kind"],
                         "dereference_of_field_derived_pointer")
        self.assertEqual(r["dynamic_pointer_accesses"][0]["pointer_provenance"]
                         ["root_global_field_offset"],0x5A8)

    def test_unknown_base_is_not_attributed_to_global_object(self):
        image=image_with(0x1000,bytes.fromhex("53600460"))
        r=m.scan_range(image,"synthetic",0x1000,0x1004,{"r0":0x568})
        self.assertEqual(r["stores_via_known_alias"],[])

    def test_invalid_range_rejected(self):
        image=bytes(b"\xff"*m.SIZE)
        for start,end in [(0x1001,0x1004),(0x1000,0x1001),(0x1004,0x1000)]:
            with self.subTest(start=start,end=end),self.assertRaises(ValueError):
                m.scan_range(image,"synthetic",start,end,{"r0":0})

    def test_wrong_image_size_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            m.audit(b"\xff"*(m.SIZE-1))

    def test_wrong_sha_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(b"\xff"*m.SIZE)

    def test_hash_matched_synthetic_image_still_rejects_wrong_function_bytes(self):
        image=b"\xff"*m.SIZE
        digest=hashlib.sha256(image).hexdigest()
        with self.assertRaisesRegex(ValueError,"Code fingerprint mismatch"):
            m.audit(image,expected_sha256=digest)

    def test_callback_offsets_are_not_confused_with_nearby_fields(self):
        self.assertEqual(m.callback_fields_overlapped(0x5DC,4),[])
        self.assertEqual(m.callback_fields_overlapped(0x6C0,4),[])
        self.assertEqual(m.callback_fields_overlapped(0x5F8,4),["bulk_in_handler"])

    def test_analysis_stays_explicit_about_unresolved_runtime_claims(self):
        self.assertEqual(m.SHA256,"59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0")
        self.assertEqual(set(m.CALLBACK_FIELDS.values()),
                         {"bulk_in_handler","bulk_in_context","bulk_out_handler","bulk_out_context"})
        self.assertIn("No whole-program CFG",m.__doc__ or "No whole-program CFG")


if __name__=="__main__":
    unittest.main()
