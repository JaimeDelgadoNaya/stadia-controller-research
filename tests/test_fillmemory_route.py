"""Synthetic read-only FillMemory route tests; never use OEM firmware in CI."""
import hashlib
import struct
import unittest

from tools import audit_fillmemory_route as m


def encode_bl(source, target):
    rel=target-source-4
    if rel & 1 or not -(1 << 24) <= rel < (1 << 24):
        raise ValueError("Unrepresentable Thumb BL")
    imm=rel & ((1<<25)-1)
    s=(imm>>24)&1
    i1=(imm>>23)&1
    i2=(imm>>22)&1
    j1=1^(i1^s)
    j2=1^(i2^s)
    first=0xf000|(s<<10)|((imm>>12)&0x3ff)
    second=0xd000|(j1<<13)|(j2<<11)|((imm>>1)&0x7ff)
    return struct.pack("<HH",first,second)


def fixture(with_secondary_policy_call=False):
    data=bytearray(m.SIZE)
    data[m.FILL_CODE_RANGE[0]:m.FILL_CODE_RANGE[1]]=b"\x00\xbf"*16
    for tag,handler,enable in [
        (4,0x200030d9,1),(5,m.FILL_HANDLER,1),
        (9,0x200033a1,0),(10,0x2000340d,0),
    ]:
        struct.pack_into("<3I",data,m.TABLE+(tag-1)*12,handler,0,enable)
    # Synthetic handler invokes helper at 0x20003480.
    data[0x3384:0x3388]=encode_bl(m.BASE+0x3384,m.BASE+0x3480)
    data[0x3480:0x3500]=b"\x00\xbf"*64
    if with_secondary_policy_call:
        data[0x3488:0x348c]=encode_bl(m.BASE+0x3488,m.TRACKED_WRITEMEMORY_POLICY)
    return bytes(data)


def fake_audit(data, **kw):
    return m.summarize(data,expected_sha=hashlib.sha256(data).hexdigest(),**kw)


class FillMemoryRouteTests(unittest.TestCase):
    def test_synthetic_does_not_pass_actual_image_hash(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            m.summarize(fixture())

    def test_fill_enabled_but_execute_and_call_disabled(self):
        report=fake_audit(fixture())
        table=report["table"]
        self.assertTrue(table["FillMemory"]["dispatches"])
        self.assertTrue(table["WriteMemory"]["dispatches"])
        self.assertFalse(table["Execute"]["dispatches"])
        self.assertFalse(table["Call"]["dispatches"])

    def test_fill_has_no_packet_data_phase(self):
        protocol=fake_audit(fixture())["protocol"]
        self.assertEqual(protocol["tag"],"0x05")
        self.assertFalse(protocol["payload_report_stage"])
        self.assertEqual(protocol["pattern_width_bits"],32)
        self.assertTrue(protocol["distinct_from_WriteMemory_fragment_gate"])

    def test_first_level_direct_call_is_detected(self):
        result=fake_audit(fixture())
        self.assertEqual(result["fill_handler"]["direct_call_targets"],["0x20003480"])
        self.assertEqual(len(result["first_level_callee_previews"]),1)
        self.assertEqual(result["first_level_callee_previews"][0]["target"],"0x20003480")

    def test_second_level_known_policy_edge_can_be_seen(self):
        report=fake_audit(fixture(with_secondary_policy_call=True))
        self.assertTrue(report["tracked_WriteMemory_policy_hits_in_bounded_previews"][
            "known_WriteMemory_range_policy"])
        self.assertEqual(report["conclusions"]["FillMemory_uses_same_write_policy"],
                         "NOT ESTABLISHED from a bounded preview")

    def test_absent_policy_in_preview_is_not_bypass_claim(self):
        r=fake_audit(fixture())
        self.assertFalse(r["tracked_WriteMemory_policy_hits_in_bounded_previews"][
            "known_WriteMemory_range_policy"])
        self.assertEqual(r["conclusions"]["FillMemory_can_modify_execution_gate"],
                         "NOT DEMONSTRATED")

    def test_wrong_table_handler_rejected(self):
        data=bytearray(fixture())
        struct.pack_into("<I",data,m.TABLE+12*(5-1),0x20001001)
        with self.assertRaisesRegex(ValueError,"table"):
            fake_audit(bytes(data))

    def test_disabled_fill_tag_rejected(self):
        data=bytearray(fixture())
        struct.pack_into("<I",data,m.TABLE+12*(5-1)+8,0)
        with self.assertRaisesRegex(ValueError,"table"):
            fake_audit(bytes(data))

    def test_enabling_execute_tag_does_not_pass_gate(self):
        data=bytearray(fixture())
        struct.pack_into("<I",data,m.TABLE+12*(9-1)+8,1)
        with self.assertRaisesRegex(ValueError,"table"):
            fake_audit(bytes(data))

    def test_invalid_loader_length_rejected(self):
        data=fixture()[:-1]
        with self.assertRaisesRegex(ValueError,"size mismatch"):
            fake_audit(data)

    def test_truncated_code_window_rejected(self):
        data=fixture()
        with self.assertRaises(ValueError):
            m.decode_window(data,0x3381,0x33a0)
        with self.assertRaises(ValueError):
            m.decode_window(data,0x3380,m.CODE_CUTOFF+2)

    def test_invalid_preview_size_rejected(self):
        for size in (0,15,17,258):
            with self.subTest(size=size),self.assertRaises(ValueError):
                fake_audit(fixture(),preview_bytes=size)

    def test_no_device_or_flash_actions(self):
        r=fake_audit(fixture())
        self.assertFalse(r["device_access"])
        self.assertFalse(r["hid_requests"])
        self.assertFalse(r["flash_or_fuse_writes"])
        self.assertEqual(r["conclusions"]["unsigned_custom_code_execution"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["conclusions"]["recovery_after_bad_write"],"NOT VERIFIED")


if __name__=="__main__":
    unittest.main()
