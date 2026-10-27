"""Synthetic-only regression suite for SRC_GPR7 writer provenance, phase 88."""
import copy
import json
from pathlib import Path
import struct
import unittest

from tools.audit_src_gpr7_writers_phase88 import (
    SRC_BASE, SRC_GPR6, SRC_GPR7, UPDATE_BIT, IMAGE_CONSTANTS,
    raw_src_constant_census, selected_bootloader_writers, audit_selected,
    audit_public_original,
)

ORIGINAL = Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json"


class SourceWriterPhase88(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus=json.loads(ORIGINAL.read_text(encoding="utf-8"))

    def test_nxp_absolute_register_address_correction(self):
        self.assertEqual(SRC_GPR6,0x400F8034)
        self.assertEqual(SRC_GPR7,0x400F8038)
        self.assertNotEqual(SRC_GPR6,SRC_GPR7)
        self.assertEqual(SRC_GPR7-SRC_BASE,0x38)
        self.assertEqual(UPDATE_BIT,0x08)

    def test_selected_corpus_28_functions_903_instructions(self):
        out=selected_bootloader_writers(self.corpus)
        self.assertEqual(out["selected_functions"],28)
        self.assertEqual(out["selected_instructions"],903)
        self.assertFalse(out["complete_binary_writer_census"])

    def test_two_base_literal_sources_are_pinned(self):
        out=selected_bootloader_writers(self.corpus)
        self.assertEqual({e["site"] for e in out["src_base_literal_loads"]},
                         {"0x60801f0c","0x60802860"})

    def test_signed_clear_store_does_not_set_bit3(self):
        stores=selected_bootloader_writers(self.corpus)["directly_attributed_gpr7_stores"]
        clear=next(e for e in stores if e["site"]=="0x6080286a")
        self.assertEqual(clear["classification"],"clear")
        self.assertEqual(clear["values_in_pinned_local_path"],["0x00"])
        self.assertEqual(clear["destination"],"0x400f8038")
        self.assertFalse(clear["sets_update_bit3"])

    def test_signed_status_store_does_not_set_bit3(self):
        stores=selected_bootloader_writers(self.corpus)["directly_attributed_gpr7_stores"]
        status=next(e for e in stores if e["site"]=="0x60801f14")
        self.assertEqual(status["classification"],"application_validation_status")
        self.assertEqual(status["values_in_pinned_local_path"],["0x10","0x20"])
        self.assertFalse(status["sets_update_bit3"])

    def test_no_host_or_rom_writer_inferred(self):
        a=audit_selected(self.corpus)
        self.assertEqual(a["selected_bootloader_a"]["known_selected_stores_setting_bit3"],0)
        self.assertEqual(a["open_questions"]["who_sets_gpr7_bit3"],"UNKNOWN")
        self.assertEqual(a["open_questions"]["rom_writes_gpr7_bit3"],"NOT_DEMONSTRATED")
        self.assertEqual(a["open_questions"]["usb_control_of_bit3"],"NOT_DEMONSTRATED")

    def test_source_mutation_early_failure(self):
        changed=copy.deepcopy(self.corpus)
        for f in changed["functions"]:
            for i in f["instructions"]:
                if i["address"]=="0x6080286a":
                    i["bytes"]="ffff"
        with self.assertRaises(ValueError):
            selected_bootloader_writers(changed)

    def test_base_literal_mutation_early_failure(self):
        changed=copy.deepcopy(self.corpus)
        for f in changed["functions"]:
            for i in f["instructions"]:
                if i["address"]=="0x60801f0c":
                    i["literal_uint32"]="0x400f8034"
        with self.assertRaises(ValueError):
            selected_bootloader_writers(changed)

    def test_synthetic_raw_word_census_has_three_distinct_categories(self):
        data=bytearray(b"\xff"*128)
        for at,value in ((4,SRC_GPR6),(16,SRC_GPR7),(32,SRC_BASE)):
            struct.pack_into("<I",data,at,value)
        hits=raw_src_constant_census(bytes(data),len(data))
        self.assertEqual([x["name"] for x in hits],
          ["src_gpr6_distinct_register","src_gpr7","src_base"])
        self.assertTrue(all(not x["instruction_xref_proven"] for x in hits))
        self.assertTrue(all(not x["writer_reachable_or_executed"] for x in hits))

    def test_halfword_aligned_raw_word_not_executed(self):
        data=bytearray(b"\xff"*32)
        struct.pack_into("<I",data,2,SRC_GPR7)
        hits=raw_src_constant_census(bytes(data),32)
        self.assertEqual(len(hits),1)
        self.assertEqual(hits[0]["alignment"],"halfword_only")
        self.assertFalse(hits[0]["writer_reachable_or_executed"])

    def test_pre_csf_boundary_prevents_false_trailer_count(self):
        data=bytearray(b"\xff"*128)
        struct.pack_into("<I",data,120,SRC_GPR7)
        self.assertEqual(raw_src_constant_census(bytes(data),120),[])
        self.assertEqual(len(raw_src_constant_census(bytes(data),128)),1)

    def test_raw_scan_rejects_bad_bounds_and_type(self):
        for data,limit in ((b"",1),(bytes(20),21),(bytes(20),-1),(bytearray(16),16)):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    raw_src_constant_census(data,limit)

    def test_exact_public_signed_image_hash_is_mandatory(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            audit_public_original(bytes(100672),"restricted_ram_loader")

    def test_reset_value_does_not_prove_warm_reset_behavior(self):
        x=audit_selected(self.corpus)
        self.assertEqual(x["nxp_register_map"]["gpr7_documented_reset_value"],
                         "0x00000000")
        self.assertEqual(x["open_questions"]["warm_reset_persistence_on_controller"],
                         "NOT_MEASURED")


if __name__=="__main__":
    unittest.main()
