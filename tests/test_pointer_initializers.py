"""Synthetic Phase-26 tests. No proprietary Stadia image is embedded or required."""
import hashlib
import struct
import unittest

from tools import audit_pointer_initializers as m


def fixture():
    data=bytearray(b"\xff"*m.SIZE)
    for at,text in m.ANCHORS.items():
        raw=bytes.fromhex(text)
        data[at:at+len(raw)]=raw
    return bytes(data)


def synthetics(data):
    regions={k:(start,end,hashlib.sha256(data[start:end]).hexdigest())
             for k,(start,end,_) in m.REGIONS.items()}
    return m.audit(data,expected_sha256=hashlib.sha256(data).hexdigest(),
                   fingerprints=regions)


class InitialPointerProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake=fixture()

    def test_default_sha_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.audit(self.fake)

    def test_two_pointer_fields_have_identical_initial_target(self):
        got=synthetics(self.fake)["normal_constructor_pointer_initialization"]
        self.assertEqual(got["computed_pointer_value"],"0x20008cac")
        self.assertEqual([row["initial_value"] for row in got["pointer_fields"]],
                         ["0x20008cac","0x20008cac"])
        self.assertEqual([row["ram_field_address"] for row in got["pointer_fields"]],
                         ["0x200090d8","0x200090e0"])
        self.assertEqual([row["constructor_store"] for row in got["pointer_fields"]],
                         ["0x6080baec","0x6080baf2"])

    def test_global_plus_570_is_not_a_pointer_initializer(self):
        field=synthetics(self.fake)["normal_constructor_pointer_initialization"][
            "field_global_plus_0x570"]
        self.assertEqual(field["ram_address"],"0x200090e8")
        self.assertEqual(field["byte_initial_value"],0)
        self.assertIn("BYTE FIELD",field["correction"])

    def test_transferred_initial_parameters_remain_below_callback_fields(self):
        obj=synthetics(self.fake)["normal_constructor_pointer_initialization"]
        addr=obj["initial_parameter_addresses_for_0x60809048"]
        self.assertEqual(addr["input+0x154"],"0x20008e00")
        self.assertEqual(addr["input+0x158"],"0x20008e04")
        self.assertEqual(addr["input+0x15c"],"0x20008e08")
        self.assertTrue(obj["all_initial_parameter_addresses_below_callback_fields"])
        self.assertTrue(all(int(x,16)<m.GLOBAL+min(m.CALLBACK_OFFSETS)
                            for x in addr.values()))

    def test_first_list_head_self_referential_initialization(self):
        head=synthetics(self.fake)["linked_list_head_initialization"]["heads"][0]
        self.assertEqual(head["base"],"0x20009114")
        self.assertEqual(head["count_field"]["value"],"0x00000000")
        self.assertEqual(head["next_field"]["value"],"0x2000911c")
        self.assertEqual(head["link_field"]["value"],"0x2000911c")
        self.assertEqual(head["owner_or_link_field"]["value"],"0x2000911c")
        self.assertEqual(head["marker_field"]["value"],"0xffffffff")
        self.assertIn("NOT a pointer",head["marker_field"]["type"])

    def test_second_list_head_self_referential_initialization(self):
        head=synthetics(self.fake)["linked_list_head_initialization"]["heads"][1]
        self.assertEqual(head["base"],"0x20009128")
        self.assertEqual(head["next_field"]["value"],"0x20009130")
        self.assertEqual(head["link_field"]["value"],"0x20009130")

    def test_exact_two_initial_list_calls(self):
        result=synthetics(self.fake)["linked_list_head_initialization"]
        self.assertEqual(result["head_arguments"],["0x20009114","0x20009128"])
        self.assertEqual(result["two_direct_calls"],[
            "0x60810b9c -> 0x6081099c","0x60810ba4 -> 0x6081099c"])

    def test_selected_raw_strw_scan_has_one_site_each(self):
        got=synthetics(self.fake)["thumb2_strw_census"]["raw_positive_immediate_matches"]
        self.assertEqual([row["at"] for row in got["0x560"]],["0x6080baec"])
        self.assertEqual([row["at"] for row in got["0x568"]],["0x6080baf2"])

    def test_alternate_source_register_is_detected_not_silently_ignored(self):
        blob=bytearray(self.fake)
        struct.pack_into("<HH",blob,0x1110,0xF8C1,0x7560)
        with self.assertRaisesRegex(ValueError,"candidate census changed"):
            synthetics(bytes(blob))

    def test_wrong_direct_constructor_call_rejected(self):
        blob=bytearray(self.fake)
        blob[0x10B9C]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            synthetics(bytes(blob))

    def test_corrupt_zero_byte_store_detected(self):
        blob=bytearray(self.fake)
        blob[0xBAE8]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            synthetics(bytes(blob))

    def test_corrupt_node_init_detected(self):
        blob=bytearray(self.fake)
        blob[0x109A8]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor"):
            synthetics(bytes(blob))

    def test_mutation_outside_anchors_with_fixed_digest_is_detected(self):
        regions={k:(start,end,hashlib.sha256(self.fake[start:end]).hexdigest())
                 for k,(start,end,_) in m.REGIONS.items()}
        blob=bytearray(self.fake)
        blob[0xBAE6]^=1
        with self.assertRaisesRegex(ValueError,"Machine code region mismatch"):
            m.audit(bytes(blob),expected_sha256=hashlib.sha256(blob).hexdigest(),
                    fingerprints=regions)

    def test_length_rejected(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            synthetics(self.fake[:-1])

    def test_invalid_link_head_address(self):
        for val in (-1,3,0xfffffff1,None):
            with self.subTest(val=val),self.assertRaises((ValueError,TypeError)):
                m.initialized_list_head(val)

    def test_no_claim_of_runtime_override_or_bypass(self):
        r=synthetics(self.fake)
        self.assertEqual(r["claims"]["later_field_mutation"],"NOT PROVEN OR EXCLUDED")
        self.assertEqual(r["claims"]["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(r["claims"]["host_usb_to_flash_writer"],"NOT DEMONSTRATED")
        self.assertFalse(r["usb_transactions"])
        self.assertFalse(r["hardware_access"])


if __name__=="__main__":
    unittest.main()
