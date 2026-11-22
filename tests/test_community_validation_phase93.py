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
        cls.patch = load("community-bootloader-patch-phase93.json")
        cls.ram_loader = load("nxp-ram-flashloader-phase93.json")
        cls.bruce_kvs = load("bruce-kvs-registry-phase93.json")
        cls.stadiacast = load("stadiacast-upstream-phase93.json")
        cls.field_return = load("field-return-risk-phase93.json")

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
        self.assertEqual(own["full_offline_suite"]["tests_run"], 1061)
        self.assertEqual(own["full_offline_suite"]["skipped"], 35)
        self.assertEqual(own["bounded_original_and_emulation_lane"]["tests_run"], 89)
        self.assertEqual(own["phase93_integrity"]["tests_per_run"], 21)
        self.assertEqual(own["phase93_bootloader_fixtures"]["tests_per_run"], 22)
        self.assertEqual(own["phase93_bruce_kvs"]["tests_per_run"], 6)

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
        self.assertEqual(s["release"], "v1.3.0")
        self.assertTrue(s["ota_282115_end_to_end"])
        self.assertTrue(s["no_firmware_modification"])
        self.assertEqual(s["hosts"]["fvc"], "cloudcast-pa.googleapis.com")
        self.assertEqual(s["hosts"]["gmsg"], "cloudcast-gmsg-prod.googleapis.com")
        self.assertTrue(s["gmsg_delivers_webrtc_answer"])
        self.assertFalse(s["direct_switch2_compatibility_verified"])

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

    def test_private_bootloader_patch_is_exactly_bounded(self):
        d = self.patch["direct_byte_comparison"]
        self.assertEqual(d["changed_bytes"], 72)
        self.assertEqual(d["changed_outside_ivt_code_descriptor"], 0)
        self.assertEqual(d["tail_removed_bytes"], 36824)
        self.assertEqual(self.patch["source_files"]["oem"]["size_bytes"], 131072)
        self.assertEqual(self.patch["source_files"]["candidate"]["size_bytes"], 94248)

    def test_patch_keeps_device_identity_but_replaces_hid_with_cdc(self):
        self.assertTrue(self.patch["usb_device_descriptor"]["identical"])
        self.assertEqual(self.patch["usb_device_descriptor"]["vid"], "0x18d1")
        self.assertEqual(self.patch["usb_device_descriptor"]["pid"], "0x946b")
        self.assertEqual(self.patch["oem_configuration"]["interface_classes"], ["0xff", "0x03"])
        self.assertEqual(self.patch["candidate_configuration"]["interface_classes"], ["0xff", "0x02/0x02", "0x0a"])
        self.assertEqual(self.patch["candidate_configuration"]["cdc_union"], {"master": 1, "slaves": [2]})

    def test_one_code_byte_updates_usb_descriptor_length(self):
        p = self.patch["code_change"]
        self.assertEqual(p["oem_thumb_halfword"], "5023")
        self.assertEqual(p["candidate_thumb_halfword"], "5523")
        self.assertTrue(p["immediate_matches_oem_config_length"])
        self.assertTrue(p["immediate_matches_candidate_config_length"])
        self.assertEqual(p["descriptor_pointer_literal"], "0x6081527c")
        self.assertTrue(p["pointer_unchanged"])

    def test_candidate_clears_csf_and_omits_original_csf_tail(self):
        a = self.patch["authentication"]
        self.assertEqual(self.patch["ivt"]["oem"]["csf"], "0x60818000")
        self.assertEqual(self.patch["ivt"]["candidate"]["csf"], "0x0")
        self.assertEqual(a["oem_csf_header_at_file_offset_0x18000"], "d4006042")
        self.assertTrue(a["candidate_ends_before_csf_offset"])
        self.assertFalse(a["candidate_original_signature_verified"])

    def test_separate_ram_flashloader_is_hid_not_cdc(self):
        r = self.ram_loader
        self.assertEqual(r["ivt"]["entry"], "0x20002000")
        self.assertEqual(r["ivt"]["csf"], "0x0")
        self.assertEqual(r["boot_data"]["file_shortfall_bytes"], 156)
        self.assertEqual(r["usb_device"]["vid"], "0x15a2")
        self.assertEqual(r["usb_device"]["pid"], "0x0073")
        self.assertEqual(r["usb_configuration"]["interfaces"], 1)
        self.assertEqual(r["usb_configuration"]["endpoints"][0]["transfer"], "interrupt")
        self.assertTrue(r["transport_name_markers"]["CDC"])
        self.assertFalse(r["usb_configuration"]["cdc_union_present"])

    def test_bruce_kvs_ids_are_version_specific_not_gotham(self):
        k = self.bruce_kvs
        self.assertEqual(k["table"]["contiguous_sequential_entries"], 66)
        self.assertEqual(k["selected_id_to_name"]["21"], "AnalyticsOptIn")
        self.assertEqual(k["selected_id_to_name"]["22"], "LastKnownSntp")
        self.assertEqual(k["selected_id_to_name"]["23"], "IsDfDevice")
        self.assertEqual(k["selected_id_to_name"]["40"], "AppImageFdrVer")
        self.assertEqual(k["selected_id_to_name"]["44"], "LogToUart")
        self.assertFalse(k["yeti_ascii_literals"]["YetiGmsgUrl"])
        self.assertTrue(k["limits"]["sample_is_bruce_not_gotham"])

    def test_stadiacast_upstream_confirms_stock_wifi_path(self):
        s = self.stadiacast
        self.assertTrue(s["claims_verified_in_upstream_source"]["works_end_to_end_with_wifi_firmware_ota_282115"])
        self.assertTrue(s["claims_verified_in_upstream_source"]["no_controller_firmware_modification_required"])
        self.assertEqual(s["claims_verified_in_upstream_source"]["fvc_hosts"], ["cloudcast-pa.googleapis.com"])
        self.assertEqual(s["claims_verified_in_upstream_source"]["gmsg_host"], "cloudcast-gmsg-prod.googleapis.com")
        self.assertTrue(s["claims_verified_in_upstream_source"]["gmsg_delivers_webrtc_answer_bundle"])
        self.assertFalse(s["limits"]["direct_Switch_2_compatibility_verified"])

    def test_field_return_is_explicit_no_go_for_rt1061(self):
        f = self.field_return
        self.assertEqual(f["decision"], "NO_GO")
        self.assertFalse(f["applicability"]["exact_rt1061_field_return_fuse_mapping_verified"])
        self.assertFalse(f["actions"]["fuses_written"])
        self.assertEqual(f["documented_facts"]["rt1060_manual_field_return_fuse"], "0x400[31]")

    def test_no_destructive_or_live_actions_occurred(self):
        s = self.report["safety"]
        for key, value in s.items():
            if key != "author_request_for_no_duplicate_switch_firmware_respected":
                self.assertFalse(value, key)
        self.assertTrue(s["author_request_for_no_duplicate_switch_firmware_respected"])


if __name__ == "__main__":
    unittest.main()
