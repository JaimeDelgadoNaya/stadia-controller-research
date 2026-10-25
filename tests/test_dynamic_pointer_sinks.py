"""Synthetic phase-25 verification of opaque pointer sink boundaries."""
import hashlib
import struct
import unittest

from tools import audit_dynamic_pointer_sinks as m


def encode_bl(source, target):
    """Encode Thumb BL immediate for a synthetic fixture."""
    disp = m.BASE + target - (m.BASE + source + 4)
    if disp & 1 or not -(1<<24) <= disp < (1<<24):
        raise ValueError("Target outside Thumb BL span")
    bits=disp & ((1<<25)-1)
    s=(bits>>24)&1
    i1=(bits>>23)&1
    i2=(bits>>22)&1
    j1=1^(i1^s)
    j2=1^(i2^s)
    h1=0xF000|(s<<10)|((bits>>12)&0x3ff)
    h2=0xD000|(j1<<13)|(j2<<11)|((bits>>1)&0x7ff)
    return struct.pack("<HH",h1,h2)


def fixture():
    data=bytearray(b"\xff"*m.SIZE)
    for site,(raw,_) in m.INSTRUCTIONS.items():
        value=bytes.fromhex(raw)
        data[site:site+len(value)] = value
    for site,target in m.DIRECT_EDGES.items():
        value=encode_bl(site,target)
        data[site:site+len(value)] = value
    return bytes(data)


def test_scan(data, regions=None):
    if regions is None:
        regions={name:(start,end,hashlib.sha256(data[start:end]).hexdigest())
                 for name,(start,end,_) in m.REGIONS.items()}
    return m.scan(data,expected_sha256=hashlib.sha256(data).hexdigest(),
                  ranges=regions)


class DynamicPointerSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake=fixture()

    def test_sha_lock_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.scan(self.fake)

    def test_fake_has_expected_size(self):
        self.assertEqual(len(self.fake),131072)

    def test_all_direct_calls_decoded(self):
        result=test_scan(self.fake)
        self.assertEqual(len(result["direct_calls"]),len(m.DIRECT_EDGES))
        self.assertEqual(
            {x["callsite"]:x["target"] for x in result["direct_calls"]},
            {m.fmt(a):m.fmt(b) for a,b in m.DIRECT_EDGES.items()})

    def test_opaque_transfer_routine_does_not_claim_host_parser(self):
        result=test_scan(self.fake)
        detail=result["transfer_routine"]
        self.assertEqual(detail["entry"],"0x60809048")
        self.assertIn("input+0xf8",detail["argument_derivations"])
        self.assertTrue(detail["not_yet_a_usb_packet_parser"])
        self.assertEqual(detail["direct_stores_through_input"],
                         "NONE IN ATTESTED REGION")

    def test_list_unlink_tracks_unknown_pointer_stores(self):
        detail=test_scan(self.fake)["linked_list_unlink"]
        self.assertEqual(len(detail["writes"]),5)
        self.assertEqual(detail["writes"][0]["destination"],"previous + 0x08")
        self.assertFalse(detail["any_write_address_proven_to_be_usb_callback_field"])
        self.assertFalse(detail["absence_of_runtime_aliasing_proven"])

    def test_callsite_derivation_is_stated_as_unknown(self):
        detail=test_scan(self.fake)["linked_list_unlink"]["caller_chain"]
        self.assertEqual(detail["calls_with_pointers"],
                         ["link+0x18","sometimes link+0x04"])
        self.assertEqual(detail["dynamic_objects"],"NOT RESOLVED")

    def test_no_false_security_claims(self):
        c=test_scan(self.fake)["conclusions"]
        self.assertEqual(c["hab_closed_bypass"],"NOT DEMONSTRATED")
        self.assertEqual(c["custom_firmware_execution"],"NOT DEMONSTRATED")
        self.assertEqual(c["host_to_flash_writer"],"NOT DEMONSTRATED")
        self.assertEqual(c["pointer_alias_to_callback_fields"],"NOT PROVEN OR EXCLUDED")

    def test_image_size_mismatch(self):
        with self.assertRaisesRegex(ValueError,"131072"):
            test_scan(self.fake[:-1])

    def test_incorrect_stored_region_digest(self):
        bad=dict(m.REGIONS)
        with self.assertRaisesRegex(ValueError,"Code-region SHA mismatch"):
            test_scan(self.fake,regions=bad)

    def test_local_region_mutation_rejected(self):
        altered=bytearray(self.fake)
        altered[0x9074]^=1
        reference={name:(start,end,hashlib.sha256(self.fake[start:end]).hexdigest())
                   for name,(start,end,_) in m.REGIONS.items()}
        with self.assertRaisesRegex(ValueError,"Code-region SHA mismatch"):
            test_scan(bytes(altered),reference)

    def test_changed_instruction_anchor_rejected(self):
        altered=bytearray(self.fake)
        altered[0x10A04]^=1
        with self.assertRaisesRegex(ValueError,"Instruction anchor mismatch"):
            test_scan(bytes(altered))

    def test_changed_bl_target_rejected(self):
        altered=bytearray(self.fake)
        altered[0x9062:0x9066]=encode_bl(0x9062,0x101BC)
        with self.assertRaisesRegex(ValueError,"Direct BL edge changed"):
            test_scan(bytes(altered))

    def test_invalid_region_bounds_rejected(self):
        regions={name:(start,end,digest) for name,(start,end,digest) in m.REGIONS.items()}
        regions["transfer_opaque_pointee"]=(0,0,"deadbeef")
        with self.assertRaisesRegex(ValueError,"Invalid attested range"):
            test_scan(self.fake,regions)

    def test_unknown_bytes_outside_regions_do_not_change_scope(self):
        altered=bytearray(self.fake)
        altered[0x15000]^=1
        actual=test_scan(bytes(altered))
        self.assertTrue(actual["sha256_verified"])
        self.assertFalse(actual["device_access"])

    def test_private_image_is_not_embedded_in_repository(self):
        self.assertEqual(len(m.SHA256),64)
        self.assertEqual(set(m.REGIONS),
                         {"transfer_opaque_pointee","list_unlink_opaque_node","list_caller"})


if __name__=="__main__":
    unittest.main()
