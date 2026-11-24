"""Read-only SHA-gated public RT1060 ROM excerpt tests."""
import unittest
from research.phase98.inspect_rom import inspect_rom, ROM_SIZE, ROM_SHA, ROM_BASE, REGIONS

class StaticRomPhase98Tests(unittest.TestCase):
    def test_reference_requires_128_kib(self):
        with self.assertRaisesRegex(ValueError, "131072"):
            inspect_rom(b"")

    def test_requires_known_hash(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            inspect_rom(b"\x00" * ROM_SIZE)

    def test_no_unverified_candidate_as_reference(self):
        self.assertEqual(len(ROM_SHA), 64)
        self.assertEqual(ROM_BASE, 0x00200000)

    def test_functions_within_rom(self):
        for ref in REGIONS.values():
            self.assertTrue(0 <= ref["address"] - ROM_BASE < ROM_SIZE)
            self.assertLessEqual(ref["address"] - ROM_BASE + ref["length"], ROM_SIZE)
            self.assertEqual(ref["address"] % 2, 0)

    def test_regions_do_not_overlap(self):
        spans = sorted((v["address"], v["address"] + v["length"]) for v in REGIONS.values())
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))

if __name__ == "__main__":
    unittest.main(verbosity=2)
