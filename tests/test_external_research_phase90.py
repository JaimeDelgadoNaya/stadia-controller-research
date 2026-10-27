"""Offline, fail-closed tests for external research comparison phase90."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.audit_external_research_phase90 import (
    UPSTREAM, git_blob_sha1,verified_upstream_text,
    recovery_source_audit,hab_precondition_audit,gotham_evidence_audit,
)

EVIDENCE=Path(__file__).resolve().parents[1]/"evidence"


def originals():
    return [json.loads((EVIDENCE/x).read_text(encoding="utf-8")) for x in (
        "nxp-rom-csf-phase81.json","hab-rom-version-phase83.json",
        "bootloader-update-transaction-phase86.json")]


def fake_upstream():
    # Strings match pinned-code anchors, but all tests use harmless comment text.
    st="""# def dumpFlash(dev):
# fl.read32(0x402A8100)
# fl.set32(0x402A8000 + reg, val)
# flashRead32(fl, i * 4, 4)
# setupFlash(fl, flash_type)
# def flashFirmware(dev):
# fl.flash_erase_region(0x60001000, len(ivt))
# fl.write_memory(0x60001000, ivt)
# fl.set32(0x400F8038, 0) # GPR 6
# fl.set32(0x400F8038, 1)
"""
    flash="""# Command_WriteMemory             = 0x04
# Command_FlashEraseRegion        = 0x02
"""
    sdp="""# def write_file(self, address, data):
# def jump_address(self, address):
"""
    return {
        "stadiatool/stadiatool.py":st.encode(),
        "stadiatool/flashloader.py":flash.encode(),
        "stadiatool/sdp.py":sdp.encode(),
    }


class ExternalPhase90Tests(unittest.TestCase):
    def test_git_blob_hash_known(self):
        self.assertEqual(git_blob_sha1(b"hello\n"),
                         "ce013625030ba8dba906f756967f9e9ca394464a")

    def test_git_blob_hash_rejects_non_bytes(self):
        with self.assertRaisesRegex(ValueError,"bytes"):
            git_blob_sha1("source")

    def test_unknown_public_source_path_rejected(self):
        with self.assertRaisesRegex(ValueError,"Unknown"):
            verified_upstream_text("../strange.py",b"hello")

    def test_changed_git_blob_rejected(self):
        with self.assertRaisesRegex(ValueError,"SHA1 mismatch"):
            verified_upstream_text("stadiatool/stadiatool.py",b"# tampered\n")

    def test_fake_pinned_sources_are_classified_as_source_only(self):
        sources=fake_upstream()
        pins={key:git_blob_sha1(data) for key,data in sources.items()}
        with patch.dict(UPSTREAM,pins,clear=True):
            d=recovery_source_audit(sources)
        self.assertTrue(d["dump_command_actually_writes_flexspi_registers"])
        self.assertFalse(d["dump_is_entirely_passive"])
        self.assertFalse(d["safe_recovery_after_power_failure_proven"])
        self.assertFalse(d["third_party_source_executed"])
        self.assertEqual(d["script_has_legacy_gpr_label"]["verified_nxp_register_name"],"SRC_GPR7")

    def test_upstream_missing_one_file_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"Three exact"):
            recovery_source_audit({"stadiatool/stadiatool.py":b"a"})

    def test_anchor_mutation_rejected_even_with_matching_test_sha(self):
        sources=fake_upstream()
        sources["stadiatool/stadiatool.py"]=sources["stadiatool/stadiatool.py"].replace(
            b"fl.read32(0x402A8100)",b"fl.read32(0x00)")
        pins={key:git_blob_sha1(data) for key,data in sources.items()}
        with patch.dict(UPSTREAM,pins,clear=True):
            with self.assertRaisesRegex(ValueError,"flexspi_fifo_read"):
                recovery_source_audit(sources)

    def test_existing_original_hab_sources_are_gateable(self):
        d=hab_precondition_audit(*originals())
        self.assertEqual(d["owner_rom_hab_patch_version"],"UNKNOWN_NOT_MEASURED")
        self.assertEqual(d["known_stadia_bootloader_api"],"authenticate_image_no_dcd")
        self.assertFalse(d["dcd_variant_supported_by_original_bootloader_path"])
        self.assertFalse(d["csf_tamper_bypass_in_stadia_excluded"])
        self.assertFalse(d["authenticated_custom_firmware_executable"])

    def test_tampered_dcd_precondition_rejected(self):
        a,b,c=map(copy.deepcopy,originals())
        a["audits"][0]["ivt_dcd_pointer_null"]=False
        with self.assertRaisesRegex(ValueError,"DCD"):
            hab_precondition_audit(a,b,c)

    def test_unknown_rom_version_must_remain_unknown(self):
        a,b,c=map(copy.deepcopy,originals())
        b["advisory_gate"]["owner_hab_version"]="4.2.0"
        with self.assertRaisesRegex(ValueError,"provenance"):
            hab_precondition_audit(a,b,c)

    def test_modified_csf_commands_fail_closed(self):
        a,b,c=map(copy.deepcopy,originals())
        a["audits"][1]["deprecated_command_count"]=1
        with self.assertRaisesRegex(ValueError,"CSF"):
            hab_precondition_audit(a,b,c)

    def test_postwrite_hab_must_be_present(self):
        a,b,c=map(copy.deepcopy,originals())
        c["synthetic_analysis"]["all_accepted_model_states_require_postwrite_auth"]=False
        with self.assertRaisesRegex(ValueError,"provenance"):
            hab_precondition_audit(a,b,c)

    def test_gotham_is_report_only_no_credentials(self):
        d=gotham_evidence_audit()
        self.assertFalse(d["python_gist_source_code_audited_in_this_phase"])
        self.assertFalse(d["independent_network_connection_reproduced"])
        self.assertFalse(d["credential_input_or_storage"])
        self.assertFalse(d["local_webrtc_gamepad_service_exists"])
        self.assertEqual(d["author_reported_connected_status"],"0x3c")


if __name__=="__main__":
    unittest.main()
