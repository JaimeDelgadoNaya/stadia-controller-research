"""Cross-phase integrity and evidence-boundary tests; no device access."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"


def load(name):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


class CommunityValidationPhase93(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.phase91 = load("community-phase91.json")
        cls.phase92 = load("usb-cdc-phase92.json")
        cls.phase90 = load("external-research-phase90.json")
        cls.manifest = load("manifest.json")
        cls.app_usb = load("application-usb-dispatch.json")
        cls.report = load("community-validation-phase93.json")

    def test_candidate_hash_and_size_match_across_phases(self):
        a = self.phase91["private_candidate_bootloader"]
        b = self.phase92
        self.assertEqual(a["sha256"], b["sha256"])
        self.assertEqual(a["size_bytes"], b["size_bytes"])
        self.assertEqual(b["size_bytes"], 94248)

    def test_candidate_is_not_authenticated_or_flash_safe(self):
        a = self.phase91["private_candidate_bootloader"]
        self.assertEqual(a["ivt_csf_pointer"], "0x00000000")
        self.assertFalse(a["signed_valid_confirmed"])
        self.assertFalse(a["flashing_safe_confirmed"])
        self.assertFalse(self.phase92["caveats"]["firmware_signature_verified"])

    def test_bonding_material_remains_redacted(self):
        b = self.phase91["private_bonding_candidate"]
        self.assertEqual(b["size_bytes"], 2048)
        self.assertEqual(b["recognized_prefix"], "#BONDING")
        self.assertFalse(b["contents_exported"])
        self.assertFalse(b["device_ids_exported"])
        self.assertFalse(b["hash_exported"])

    def test_usb_candidate_static_topology_is_consistent(self):
        c = self.phase92["configuration_descriptor"]
        self.assertEqual(c["wTotalLength"], 85)
        self.assertEqual(c["descriptor_count"], 12)
        self.assertEqual(c["bNumInterfaces"], 3)
        self.assertEqual(c["iad_count"], 0)
        self.assertEqual(c["cdc_union"], {"master_interface": 1, "slave_interfaces": [2]})
        self.assertTrue(c["actual_length_matches"])
        self.assertTrue(c["parsed_endpoint_counts_match"])

    def test_oem_usb_baseline_is_a_different_execution_context(self):
        o = self.phase92["baseline_comparison_phase61"]
        self.assertEqual(o["oem_device"]["pid"], "0x9400")
        self.assertEqual(o["candidate_device"]["pid"], "0x946b")
        self.assertEqual(o["oem_configuration"]["iad_count"], 2)
        self.assertEqual(o["candidate_configuration"]["iad_count"], 0)
        self.assertEqual(set(o["common_endpoints"]), {"0x07", "0x87"})
        self.assertIn("Different firmware context", o["limitations"][0])

    def test_current_application_sample_is_bruce_not_gotham(self):
        self.assertIn("Bruce", self.app_usb["sample_kind"])
        self.assertIn("unverified", self.app_usb["sample_kind"])
        self.assertEqual(self.app_usb["sha256"], "466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3")

    def test_bootloader_manifest_does_not_claim_gotham_image(self):
        self.assertEqual(self.manifest["bootloader_build"], 169429)
        self.assertFalse(self.manifest["publication"]["full_firmware_binaries_included"])
        self.assertNotIn("ota.282115", json.dumps(self.manifest))

    def test_prior_gotham_provisioning_lead_is_unverified(self):
        g = self.phase90["sources"]["gotham"]
        self.assertFalse(g["script_exact_revision_verified"])
        self.assertFalse(g["script_source_audited"])
        self.assertFalse(g["independently_reproduced"])

    def test_phase91_and_92_ci_counts_are_recorded(self):
        own = self.report["own_repository"]
        self.assertEqual(own["phase91"]["tests_per_run"], 10)
        self.assertEqual(own["phase92"]["tests_per_run"], 17)
        self.assertEqual(own["full_offline_suite"]["tests_run"], 1012)
        self.assertEqual(own["full_offline_suite"]["skipped"], 34)
        self.assertEqual(own["bounded_original_and_emulation_lane"]["tests_run"], 89)

    def test_gotham_public_binary_metadata_is_pinned_but_not_claimed_audited(self):
        g = self.report["gotham_original_firmware"]
        self.assertEqual(g["repository_commit"], "c86e2a397a747ce51c0988cd967142e5324ef0f9")
        self.assertEqual(g["pvt_a"]["size_bytes"], 4163944)
        self.assertEqual(g["pvt_b"]["size_bytes"], 4163944)
        self.assertFalse(g["binary_bytes_available_in_this_analysis_session"])
        self.assertFalse(g["gotham_code_audited"])
        self.assertFalse(g["kvs_set_handler_verified"])

    def test_stadiacast_status_is_external_author_report_plus_ci(self):
        s = self.report["stadiacast_upstream"]
        self.assertEqual(s["latest_release"], "v1.3.0")
        self.assertEqual(s["python_3_11"]["passed"], 520)
        self.assertEqual(s["python_3_12"]["passed"], 520)
        self.assertEqual(s["latest_ci_run_2026_11_22"]["conclusion"], "action_required")
        self.assertEqual(s["latest_ci_run_2026_11_22"]["jobs_started"], 0)
        self.assertTrue(s["no_firmware_modification_in_receiver"])

    def test_tchebb_switch_firmware_status_not_overstated(self):
        t = self.report["tchebb_public_statement"]
        self.assertEqual(t["author_said_switch_emulation_firmware"], "not_started_at_time_of_post")
        self.assertTrue(t["author_requested_no_duplicate_zephyr_or_switch_firmware_vibe_coding"])
        self.assertFalse(t["nxp_sdp_overrun_source_accessible_for_independent_audit"])

    def test_external_esp32_project_is_classified_as_adapter_not_direct_firmware(self):
        x = self.report["additional_external_lead"]
        self.assertIn("external Wi-Fi-to-USB adapter", x["description"])
        self.assertEqual(x["relevance_to_direct_switch2_goal"], "out_of_scope_fallback_only")
        self.assertFalse(x["real_console_compatibility_independently_verified"])

    def test_community_kvs_claims_remain_unverified_and_reset_key_is_excluded(self):
        k = self.report["community_kvs_claims"]
        self.assertEqual(k["YetiDiscoUrl_registry_id_22"], "community_claim_not_verified_on_Gotham_image")
        self.assertEqual(k["YetiGmsgUrl_missing_from_registry"], "community_claim_not_verified_on_Gotham_image")
        self.assertEqual(k["usb_vendor_set_kvs_registry_enforcement"], "open_question")
        self.assertIn("excluded", k["AppImageFdrVer_id_44"])

    def test_no_destructive_or_live_actions_occurred(self):
        s = self.report["safety"]
        for key, value in s.items():
            if key != "author_request_for_no_duplicate_switch_firmware_respected":
                self.assertFalse(value, key)
        self.assertTrue(s["author_request_for_no_duplicate_switch_firmware_respected"])


if __name__ == "__main__":
    unittest.main()
