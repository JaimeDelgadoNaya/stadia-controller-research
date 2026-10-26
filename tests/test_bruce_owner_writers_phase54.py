"""Phase54 regressions: exact literal arithmetic and conservative writer tracking."""
import struct
import unittest
from tools import audit_bruce_owner_writers_phase54 as a


class Phase54WriterSearch(unittest.TestCase):
    def test_required_owner_fields(self):
        self.assertEqual(a.FIELDS[a.OWNER + 4], "class_array_pointer")
        self.assertEqual(a.FIELDS[a.OWNER + 8], "config_method_pointer")
        self.assertEqual(a.FIELDS[a.OWNER + 12], "class_count")

    def test_known_address_store_only(self):
        self.assertEqual(
            a.known_stores("str", "r2, [r4, #8]", {"r4": a.OWNER}),
            [(a.OWNER + 8, "r2")],
        )
        self.assertEqual(a.known_stores("str", "r2, [r4, #8]", {}), [])
        self.assertEqual(a.known_stores("str", "r2, [r4, r5]", {"r4": a.OWNER}), [])

    def test_byte_and_pair_stores(self):
        self.assertEqual(
            a.known_stores("strb.w", "r1, [r0, #0xc]", {"r0": a.OWNER}),
            [(a.OWNER + 12, "r1")],
        )
        self.assertEqual(
            a.known_stores("strd", "r1, r2, [r0, #4]", {"r0": a.OWNER}),
            [(a.OWNER + 4, "r1"), (a.OWNER + 8, "r2")],
        )

    def test_thumb_pc_literal_alignment(self):
        im = bytearray(0x5000)
        pc = a.BASE + 0x1012
        target = ((pc + 4) & ~3) + 4
        struct.pack_into("<I", im, target - a.BASE, a.OWNER)
        self.assertEqual(a.xip_literal(im, pc, "[pc, #4]"), a.OWNER)
        self.assertIsNone(a.xip_literal(im, pc, "[r0, #4]"))

    def test_synthetic_owner_writer_found_by_bounded_decoder(self):
        # Signed data is NOT used: 4800=LDR R0,[PC,#0]; 6041=STR R1,[R0,#4].
        blob = bytearray(0x50000)
        base = 0x60041E90 - a.BASE
        struct.pack_into("<HHI", blob, base, 0x4800, 0x6041, a.OWNER)
        result = a.trace(blob, seeds=(0x60041E90,), max_states=25, max_span=8)
        stores = result["potential_store_sites"]
        self.assertTrue(any(s["address"] == hex(a.OWNER + 4) and
                            s["site"] == "0x60041e92" for s in stores))

    def test_register_redefinition_blocks_false_writer(self):
        blob = bytearray(0x50000)
        base = 0x60041E90 - a.BASE
        # LDR R0,[PC,#0]; MOVS R0,#0; literal bytes at +4.
        struct.pack_into("<HHI", blob, base, 0x4800, 0x2000, a.OWNER)
        result = a.trace(blob, seeds=(0x60041E90,), max_states=25, max_span=8)
        self.assertEqual(result["potential_store_sites"], [])

    def test_original_sha_is_required(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            a.audit(b"unverified binary")


if __name__ == "__main__":
    unittest.main()
