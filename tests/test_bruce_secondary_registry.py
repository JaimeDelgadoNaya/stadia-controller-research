"""Synthetic-only guardrails for the bounded original Bruce class10 RAM-slot audit."""
import struct
import unittest

from tools import audit_bruce_secondary_registry as p


def fixture(*, instruction=0x6001, branch=False):
    # Thumb: LDR r0,[PC,#4] ; STR r1,[r0] ; BX LR ; NOP ; DWORD 0x20009ef8.
    blob = bytearray(0x200)
    seq = [0x4801, 0x4770 if branch else instruction,
           instruction if branch else 0x4770, 0xBF00]
    struct.pack_into("<4H", blob, 0x100, *seq)
    struct.pack_into("<I", blob, 0x108, 0x20009EF8)
    return bytes(blob)


class SecondaryRegistryTests(unittest.TestCase):
    def test_exact_target_addresses(self):
        self.assertEqual(p.TARGETS[0x20009EF8], "secondary_callback")
        self.assertEqual(p.TARGETS[0x20009EFC], "secondary_context")
        self.assertEqual(0x200064C0 + 0x3A38, 0x20009EF8)

    def test_synthetic_store_is_only_a_candidate(self):
        report = p.synthetic_walk(fixture(), 0x100, 0x10C)
        writes = [x for x in report["candidate_accesses"] if x["direction"] == "write"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["address"], "0x20009ef8")
        self.assertFalse(writes[0]["reachable_or_runtime_executed"])

    def test_synthetic_read_is_not_store(self):
        # Thumb LDR r1,[r0] = 0x6801.
        report = p.synthetic_walk(fixture(instruction=0x6801), 0x100, 0x10C)
        self.assertTrue(any(x["direction"] == "read" for x in report["candidate_accesses"]))
        self.assertFalse(any(x["direction"] == "write" for x in report["candidate_accesses"]))

    def test_branch_invalidates_literal_provenance(self):
        report = p.synthetic_walk(fixture(branch=True), 0x100, 0x10C)
        self.assertEqual(report["candidate_accesses"], [])

    def test_bad_segment_rejected(self):
        with self.assertRaises(ValueError):
            p.synthetic_walk(fixture(), 0x100, 0x10C, kind="invalid")

    def test_wrong_firmware_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            p.audit(fixture())

    def test_unresolved_register_is_not_assumed_zero(self):
        # A STORE without a preceding LDR of its address has no known target.
        data = bytearray(0x200)
        struct.pack_into("<HH", data, 0x100, 0x6001, 0x4770)
        out = p.synthetic_walk(bytes(data), 0x100, 0x104)
        self.assertEqual(out["candidate_accesses"], [])


if __name__ == "__main__":
    unittest.main()
