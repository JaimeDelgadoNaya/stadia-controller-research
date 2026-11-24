"""Tests for phase99 source contracts and signed-loader evidence gates.

All tests except optional source audit are synthetic; no hardware or code execution.
"""
import tempfile
import unittest
from pathlib import Path
from research.phase99.romc_source_contract import gate, ROMC, audit
from research.phase99.audit_signed_readmemory import entry, audit as audit_loader, SIZE, TABLE


class ROMCGateTests(unittest.TestCase):
    def test_register_geometry(self):
        self.assertEqual(ROMC, {"data":0x401800f0,"address":0x40180100,
                                "enable":0x401800fc,"control":0x401800f4})
    def test_no_rom_proven(self):
        self.assertEqual(gate(False,True,True,True,True),"BLOCKED_ROM_IDENTITY_UNKNOWN")
    def test_next_boot_requires_new_check(self):
        self.assertEqual(gate(True,True,True,True,False),"NEW_BOOT_REQUIRES_NEW_VERIFICATION")
    def test_patch_not_measured(self):
        self.assertEqual(gate(True,False,True,True,True),"PATCH_EFFECT_NOT_OBSERVED")
    def test_unsigned_load_not_measured(self):
        self.assertEqual(gate(True,True,False,True,True),"UNSIGNED_LOAD_NOT_OBSERVED")
    def test_cpu_execution_not_measured(self):
        self.assertEqual(gate(True,True,True,False,True),"CODE_EXECUTION_NOT_OBSERVED")
    def test_hypothetical_all_is_not_evidence(self):
        self.assertEqual(gate(True,True,True,True,True),
                         "ALL_GATES_HYPOTHETICALLY_ASSUMED_NOT_PROVEN")
    def test_unknown_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"main.py"
            p.write_text("SHELLCODE_ROMC = 'fake'\n")
            with self.assertRaisesRegex(ValueError,"SHA-256"):
                audit(p)


class SignedLoaderTests(unittest.TestCase):
    def test_decode_read_command_entry_from_synthetic(self):
        import struct
        data=bytearray(SIZE)
        struct.pack_into("<3I",data,TABLE+2*12,0x200035a5,0,1)
        e=entry(data,3)
        self.assertEqual(e["handler"],"0x200035a5")
        self.assertTrue(e["enabled"])
    def test_disabled_command(self):
        self.assertFalse(entry(bytes(SIZE),3)["enabled"])
    def test_wrong_binary_size_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_loader(b"")
    def test_wrong_sha_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_loader(bytes(SIZE))


if __name__=="__main__":
    unittest.main(verbosity=2)
