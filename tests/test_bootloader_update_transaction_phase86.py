"""Phase86 deterministic, offline regression cases for the bootloader A IVT flow."""
import copy
import json
from pathlib import Path
import unittest

from tools.audit_bootloader_update_transaction_phase86 import (
    PINS, audit, model, validate_corpus,
)

PATH = Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json"


class TransactionPhase86(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record=json.loads(PATH.read_text(encoding="utf-8"))

    def test_selected_source_is_pinned_before_inference(self):
        verified=validate_corpus(self.record)
        self.assertEqual(len(verified["path"]),6)
        self.assertGreater(len(PINS),25)

    def test_model_write_precedes_post_write_hab(self):
        expected=model()
        self.assertTrue(expected["accepted"])
        trace=expected["trace"]
        self.assertLess(trace.index("attempt_write_candidate_ivt_4096"),
                        trace.index("post_write_hab_auth_attempt"))
        self.assertNotIn("attempt_restore_saved_ivt_4096",trace)

    def test_all_early_gates_prevent_write(self):
        for gate in ("current_auth","candidate_structure","backup_read","power_guard","candidate_read"):
            with self.subTest(gate=gate):
                scenario=model(**{gate:False})
                self.assertEqual(scenario["writes"],[])
                self.assertFalse(scenario["post_write_auth_attempted"])
                self.assertFalse(scenario["accepted"])

    def test_structural_gate_is_not_crypto_authorization(self):
        d=model(candidate_structure=True,final_auth=False)
        self.assertIn("candidate_structure_passed_without_hab_auth",d["trace"])
        self.assertIn("post_write_hab_auth_return_failure",d["trace"])
        self.assertFalse(d["accepted"])

    def test_candidate_read_failure_has_no_install_or_rollback(self):
        d=model(candidate_read=False)
        self.assertIn("candidate_ivt_read_error_0x0a_before_write",d["trace"])
        self.assertEqual(d["writes"],[])

    def test_candidate_write_failure_attempts_restore(self):
        d=model(candidate_write=False)
        self.assertIn("attempt_write_candidate_ivt_4096",d["writes"])
        self.assertIn("attempt_restore_saved_ivt_4096",d["writes"])
        self.assertFalse(d["post_write_auth_attempted"])
        self.assertFalse(d["accepted"])

    def test_post_auth_failure_attempts_restore(self):
        d=model(final_auth=False)
        self.assertTrue(d["post_write_auth_attempted"])
        self.assertEqual(len(d["writes"]),2)
        self.assertFalse(d["accepted"])

    def test_failed_restore_still_not_success(self):
        for scenario in (model(final_auth=False,rollback_write=False),
                         model(candidate_write=False,rollback_write=False)):
            self.assertIn("rollback_return_failure_0x0f",scenario["trace"])
            self.assertFalse(scenario["accepted"])

    def test_mutated_signed_opcode_evidence_fails_closed(self):
        corrupted=copy.deepcopy(self.record)
        for f in corrupted["functions"]:
            for i in f["instructions"]:
                if i["address"]=="0x60801e84":
                    i["bytes"]="ffff"
                    with self.assertRaises(ValueError):
                        validate_corpus(corrupted)
                    return
        self.fail("expected signed instruction missing")

    def test_modified_branch_target_evidence_fails_closed(self):
        corrupted=copy.deepcopy(self.record)
        for f in corrupted["functions"]:
            for i in f["instructions"]:
                if i["address"]=="0x60801e62":
                    i["direct_target"]="0x60801f5c"
                    with self.assertRaises(ValueError):
                        validate_corpus(corrupted)
                    return
        self.fail("expected original call missing")

    def test_wrong_bootloader_version_rejected(self):
        corrupted={**self.record,"build":12345}
        with self.assertRaisesRegex(ValueError,"provenance"):
            validate_corpus(corrupted)

    def test_abstract_exhaustive_model_without_hardware_claims(self):
        out=audit(self.record)
        self.assertEqual(out["synthetic_state_combinations_checked"],256)
        self.assertTrue(out["write_before_candidate_hab_final_validation"])
        self.assertFalse(out["unsigned_code_execution_established"])
        self.assertFalse(out["physical_write_or_rollback_demonstrated"])
        self.assertFalse(out["host_controls_update_state"])
        self.assertFalse(out["power_interruption_rollback_proven"])
        self.assertFalse(out["device_access"])


if __name__=="__main__":
    unittest.main()
