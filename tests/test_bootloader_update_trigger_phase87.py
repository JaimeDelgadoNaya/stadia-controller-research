"""Synthetic-only phase87 GPR6 bit3 update-entry and provenance tests."""
import copy
import json
from pathlib import Path
import unittest

from tools.audit_bootloader_update_trigger_phase87 import (
    BASE, CALLBACK_THUMB, CONTEXT_BASE, PINS, REGISTER, STORAGE_OBJECT,
    UPDATE_MASK, audit, flag_model, validate
)

RECORD=Path(__file__).resolve().parents[1]/"evidence/bootloader-analysis.json"


class UpdateTriggerPhase87Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=json.loads(RECORD.read_text(encoding="utf-8"))

    def test_pinned_original_instructions(self):
        index=validate(self.source)
        self.assertEqual(len(PINS),30)
        self.assertEqual(index[0x608028B0]["bytes"],"2307")

    def test_only_low_byte_bit3_selects_update_call(self):
        cases=[flag_model(i) for i in range(256)]
        self.assertEqual(sum(c["update_trigger_bit3_set"] for c in cases),128)
        self.assertEqual([i for i in range(16) if flag_model(i)["update_trigger_bit3_set"]],
                         list(range(8,16)))

    def test_unrelated_application_failure_bits_do_not_trigger_update(self):
        for v in (0,0x01,0x02,0x04,0x10,0x20,0x30,0x80):
            with self.subTest(v=v):
                self.assertFalse(flag_model(v)["update_trigger_bit3_set"])

    def test_bit3_stays_triggering_with_status_bits(self):
        for v in (0x08,0x09,0x0c,0x18,0x28,0x38,0x88):
            with self.subTest(v=v):
                self.assertTrue(flag_model(v)["update_trigger_bit3_set"])

    def test_only_low_byte_remains_after_uxtb(self):
        self.assertFalse(flag_model(0x80000000)["update_trigger_bit3_set"])
        self.assertTrue(flag_model(0x40000008)["update_trigger_bit3_set"])

    def test_flag_model_has_no_host_control_claim(self):
        self.assertFalse(flag_model(0x08)["external_writer_or_usb_origin_proven"])
        self.assertTrue(flag_model(0x08)["register_cleared_by_signed_handler_before_update_call"])

    def test_parameter_provenance_is_internal_literal_not_supplied_request(self):
        report=audit(self.source)
        a=report["source_of_update_wrapper_arguments"]
        self.assertEqual(a["argument_r0_storage_context"],hex(STORAGE_OBJECT))
        self.assertEqual(a["argument_r1_callback_thumb"],hex(CALLBACK_THUMB))
        self.assertEqual(a["argument_r2_callback_context"],hex(CONTEXT_BASE))
        self.assertTrue(a["callback_is_fixed_signed_literal"])
        self.assertEqual(a["calls_coordinator"],"0x60801dd4")

    def test_sibling_gpr6_writer_is_status_0x10_or_0x20(self):
        result=audit(self.source)
        self.assertEqual(result["other_pinned_gpr6_writer"]["values"],["0x10","0x20"])
        self.assertFalse(result["other_pinned_gpr6_writer"]["complete_writer_census"])
        self.assertEqual(REGISTER,BASE+0x38)
        self.assertEqual(UPDATE_MASK,0x08)

    def test_no_unproven_reachability_assumptions(self):
        out=audit(self.source)
        self.assertEqual(out["undetermined"]["usb_host_can_set_gpr6_bit3"],"NOT_ESTABLISHED")
        self.assertEqual(out["undetermined"]["who_sets_gpr6_bit3"],"UNKNOWN")
        self.assertFalse(out["raw_original_binary_rehashed_this_phase"])
        self.assertFalse(out["device_io"])
        self.assertFalse(out["firmware_or_fuse_writes"])

    def test_bad_type_and_range_rejected(self):
        for n in (-1,2**32,True,False,None,"0x08",3.3):
            with self.subTest(n=n):
                with self.assertRaises(ValueError):
                    flag_model(n)

    def test_mutated_original_opcodes_rejected(self):
        for address in ("0x608028b0","0x608028c6","0x6080286a"):
            with self.subTest(address=address):
                edited=copy.deepcopy(self.source)
                for f in edited["functions"]:
                    for ins in f["instructions"]:
                        if ins["address"]==address:
                            ins["bytes"]="ffff"
                            with self.assertRaises(ValueError):
                                validate(edited)
                            break

    def test_modified_callback_origin_and_branch_rejected(self):
        for address,field,value in [
            ("0x608028b4","literal_uint32","0xdeadbeef"),
            ("0x608028b6","literal_uint32","0xdeadbeef"),
            ("0x608028c6","direct_target","0x60802168")
        ]:
            with self.subTest(site=address):
                edited=copy.deepcopy(self.source)
                for f in edited["functions"]:
                    for ins in f["instructions"]:
                        if ins["address"]==address:
                            ins[field]=value
                with self.assertRaises(ValueError):
                    validate(edited)


if __name__=="__main__":
    unittest.main()
