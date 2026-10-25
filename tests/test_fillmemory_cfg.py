"""Synthetic tests for FillMemory bounded CFG audit. No OEM firmware or USB."""
import hashlib
import struct
import unittest

from tools import audit_fillmemory_cfg as m


def encode_bl(source, target):
    rel = target - source - 4
    if rel & 1 or not -(1 << 24) <= rel < (1 << 24):
        raise ValueError("Thumb BL range/alignment")
    imm = rel & ((1 << 25) - 1)
    s, i1, i2 = (imm >> 24) & 1, (imm >> 23) & 1, (imm >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    return struct.pack("<HH", 0xf000 | (s << 10) | ((imm >> 12) & 0x3ff),
                       0xd000 | (j1 << 13) | (j2 << 11) | ((imm >> 1) & 0x7ff))


def fixture(*, call_policy=True, indirect=False):
    image = bytearray(m.previous.SIZE)
    image[0x3380:0x33a0] = b"\x00\xbf" * 16
    image[0x3480:0x3500] = b"\x00\xbf" * 64
    for tag, handler, enabled in [
        (4, 0x200030d9, 1), (5, 0x20003381, 1),
        (9, 0x200033a1, 0), (10, 0x2000340d, 0),
    ]:
        struct.pack_into("<3I", image, m.previous.TABLE + (tag - 1) * 12,
                         handler, 0, enabled)
    image[0x3384:0x3388] = encode_bl(m.BASE + 0x3384, m.BASE + 0x3480)
    image[0x3388:0x338a] = b"\x70\x47"  # BX LR
    if indirect:
        image[0x3480:0x3482] = b"\x98\x47"  # BLX R3
        image[0x3482:0x3484] = b"\x70\x47"
    elif call_policy:
        image[0x3480:0x3484] = encode_bl(m.BASE + 0x3480, m.KNOWN_WRITE_POLICY)
        image[0x3484:0x3486] = b"\x70\x47"
    else:
        image[0x3480:0x3482] = b"\x70\x47"
    image[0x39a8:0x39aa] = b"\x70\x47"
    return bytes(image)


def audit(image, **kw):
    return m.trace(image, expected_sha=hashlib.sha256(image).hexdigest(), **kw)


class FillMemoryCFGTests(unittest.TestCase):
    def test_classifier_covers_calls_branches_and_unknowns(self):
        self.assertEqual(m.classify("bl", 123), "call")
        self.assertEqual(m.classify("blx", None, "r3"), "indirect_call")
        self.assertEqual(m.classify("bne", 10), "conditional")
        self.assertEqual(m.classify("cbz", 10), "conditional")
        self.assertEqual(m.classify("b.w", 10), "jump")
        self.assertEqual(m.classify("bx", None, "lr"), "return")
        self.assertEqual(m.classify("bx", None, "r3"), "indirect_jump")
        self.assertEqual(m.classify("tbb", None), "indirect_jump")
        self.assertEqual(m.classify("it", None, "eq"), "it_context_unmodeled")
        self.assertEqual(m.classify("pop", None, "{r4, pc}"), "return")
        self.assertEqual(m.classify("movs", 7, "r0, #1"), "linear")

    def test_real_sha_gate_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError, "size/hash"):
            m.trace(fixture())

    def test_bounded_tracing_sees_second_level_call_without_proving_policy(self):
        report = audit(fixture())
        self.assertTrue(report["known_WriteMemory_policy_direct_call_observed"])
        self.assertFalse(report["known_WriteMemory_backend_direct_call_observed"])
        self.assertIn("NOT PROVEN", report["conclusion"]["FillMemory_same_policy"])
        self.assertFalse(report["device_access"])
        self.assertFalse(report["firmware_modification"])
        self.assertGreaterEqual(report["counts"]["functions"], 3)

    def test_no_policy_call_is_not_a_bypass(self):
        report = audit(fixture(call_policy=False))
        self.assertFalse(report["known_WriteMemory_policy_direct_call_observed"])
        self.assertIn("NOT PROVEN", report["conclusion"]["absence_of_policy"])

    def test_indirect_call_is_recorded_as_unresolved(self):
        report = audit(fixture(indirect=True))
        self.assertIn("indirect_call", report["unresolved_or_unmodeled"])
        self.assertFalse(report["known_WriteMemory_policy_direct_call_observed"])

    def test_budget_cannot_be_silent_proof(self):
        report = audit(fixture(), max_depth=0)
        self.assertIn("max_call_depth", report["unresolved_or_unmodeled"])
        self.assertFalse(report["known_WriteMemory_policy_direct_call_observed"])

    def test_gate_change_and_invalid_limits_rejected(self):
        original = fixture()
        wrong = bytearray(original)
        struct.pack_into("<I", wrong, m.previous.TABLE + (9 - 1) * 12 + 8, 1)
        with self.assertRaisesRegex(ValueError, "command table"):
            audit(bytes(wrong))
        with self.assertRaisesRegex(ValueError, "function_span"):
            audit(original, function_span=15)
        with self.assertRaisesRegex(ValueError, "budget"):
            audit(original, max_depth=9)


if __name__ == "__main__":
    unittest.main()
