"""Phase 90: three-lane, offline external-research evidence triage.

No external code execution. Public GaryOderNichts source is handled as UTF-8
TEXT only after exact Git blob SHA1 verification against a pinned upstream commit.
The Goth(am) BLE/Wi-Fi announcement is NOT an independently audited script.
NCC's HAB exploit was on another NXP chip; check preconditions conservatively.
Never connect a controller, send USB/BLE messages, read Wi-Fi credentials,
alter firmware, write registers, or attempt a flash dump/restore.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

GARY_COMMIT="1396830b449eee10e4d4de047c8db75d503f4ba3"
UPSTREAM={
    "stadiatool/stadiatool.py":"4044e32aab2ea9a849101b03ef841fe358225b3e",
    "stadiatool/flashloader.py":"60c693767e3f795c7489dd5d38895c9d564724e0",
    "stadiatool/sdp.py":"ff97d184ce4346e48b7457c5f3d772711cc9fa30",
}
GOTHAM_POST="https://www.reddit.com/r/Stadia/comments/1xfwq9w/stadia_controller_wifi_provisioning_python_script/"
GOTHAM_GIST="https://gist.github.com/supernielsen/6cb9215b21481baafe171d645542f40f"
NCC_STUDY="https://www.nccgroup.com/research/shining-new-light-on-an-old-rom-vulnerability-secure-boot-bypass-via-dcd-and-csf-tampering-on-nxp-imx-devices/"
NXP_GUIDE="https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf"


def git_blob_sha1(data):
    if not isinstance(data,bytes):
        raise ValueError("Public upstream source must be bytes")
    return hashlib.sha1(b"blob "+str(len(data)).encode("ascii")+b"\0"+data).hexdigest()


def verified_upstream_text(path,data):
    if path not in UPSTREAM:
        raise ValueError("Unknown public source path")
    if git_blob_sha1(data)!=UPSTREAM[path]:
        raise ValueError("Public source Git blob SHA1 mismatch")
    if len(data)>200_000:
        raise ValueError("Unexpectedly large upstream source")
    s=data.decode("utf-8",errors="strict")
    ast.parse(s,filename=path)  # parse only: DO NOT import or execute external code
    return s


def recovery_source_audit(sources):
    if set(sources)!=set(UPSTREAM):
        raise ValueError("Three exact original GaryOderNichts source files required")
    verified={key:verified_upstream_text(key,sources[key]) for key in UPSTREAM}
    st=verified["stadiatool/stadiatool.py"]
    flash=verified["stadiatool/flashloader.py"]
    sdp=verified["stadiatool/sdp.py"]
    anchors={
        "public_dump_function":("def dumpFlash(dev):",st),
        "flexspi_fifo_read":("fl.read32(0x402A8100)",st),
        "flexspi_register_write":("fl.set32(0x402A8000 + reg, val)",st),
        "dump_uses_flexspi_read32":("flashRead32(fl, i * 4, 4)",st),
        "dump_configures_flash":("setupFlash(fl, flash_type)",st),
        "flash_erase_function":("def flashFirmware(dev):",st),
        "ivt_erase":("fl.flash_erase_region(0x60001000, len(ivt))",st),
        "ivt_write":("fl.write_memory(0x60001000, ivt)",st),
        "gpr7_clear_legacy_comment":("fl.set32(0x400F8038, 0) # GPR 6",st),
        "gpr7_application_slot_write":("fl.set32(0x400F8038, 1)",st),
        "flashloader_write_command":("Command_WriteMemory             = 0x04",flash),
        "flashloader_erase_command":("Command_FlashEraseRegion        = 0x02",flash),
        "sdp_write_file":("def write_file(self, address, data):",sdp),
        "sdp_jump":("def jump_address(self, address):",sdp),
    }
    for key,(anchor,source) in anchors.items():
        if anchor not in source:
            raise ValueError("Verified upstream content changed expected capability: "+key)
    return {
        "evidence_type":"upstream_original_source_exact_git_blob_pinned",
        "upstream_repo":"GaryOderNichts/StadiaController",
        "upstream_commit":GARY_COMMIT,
        "verified_source_blobs":UPSTREAM,
        "capability_anchors_found":sorted(anchors),
        "flash_extraction_demonstrated_by_upstream_author":True,
        "dump_command_actually_writes_flexspi_registers":True,
        "dump_command_initializes_flash_via_restricted_loader":True,
        "dump_is_entirely_passive":False,
        "flash_erase_write_api_exists":True,
        "flashing_untrusted_unsigned_code_accepted":False,
        "safe_recovery_after_power_failure_proven":False,
        "script_has_legacy_gpr_label":{
            "actual_register_address":"0x400f8038",
            "upstream_comment":"GPR 6",
            "verified_nxp_register_name":"SRC_GPR7",
        },
        "device_actions_performed":False,
        "third_party_source_executed":False,
        "scope":"Tool source capability classification only, not owner-hardware validation.",
    }


def hab_precondition_audit(phase81,phase83,phase86):
    audits=phase81.get("audits",[])
    if len(audits)!=2 or {a.get("sample") for a in audits}!={"bruce_prod","restricted_ram_loader"}:
        raise ValueError("Original signed sample set mismatch")
    for a in audits:
        if not a.get("full_sha256_checked") or a.get("ivt_dcd_pointer_null") is not True:
            raise ValueError("Original IVT DCD provenance mismatch")
        if a.get("deprecated_command_count")!=0 or a.get("unknown_command_count")!=0:
            raise ValueError("Unexpected OEM CSF command inventory")
    if (phase83.get("advisory_gate",{}).get("owner_hab_version")!="UNKNOWN_NOT_MEASURED" or
        phase83.get("documented_rvt",{}).get("authenticate_image_no_dcd_pointer_slot")!="0x0020032c" or
        phase86.get("synthetic_analysis",{}).get("all_accepted_model_states_require_postwrite_auth") is not True):
        raise ValueError("Original HAB or bootloader authentication provenance mismatch")
    return {
        "evidence_type":"local_SHA_pinned_OEM_CSF_and_selected_owner_bootloader_instructions",
        "external_article":NCC_STUDY,
        "external_nxp_guidelines":NXP_GUIDE,
        "study_device":"i.MX6ULL development board, HAB 4.2 (not Stadia RT1060)",
        "vulnerable_version_gate":"HAB versions older than 4.3.7 (with specific loader/API use)",
        "known_stadia_bootloader_api":"authenticate_image_no_dcd",
        "published_bruce_and_ram_loader_ivt_dcd_null":True,
        "published_bruce_and_ram_loader_no_deprecated_csf_commands":True,
        "post_ivt_write_HAB_verification_modeled":True,
        "owner_rom_hab_patch_version":"UNKNOWN_NOT_MEASURED",
        "authenticated_custom_firmware_executable":False,
        "dcd_variant_supported_by_original_bootloader_path":False,
        "csf_tamper_bypass_in_stadia_excluded":False,
        "need_to_prove":[
            "physical RT1060 ROM HAB patch version",
            "candidate CSF evaluation path and effect before rejection",
            "pre-auth addressability of signed executing loader memory",
            "host-controllable candidate and safe restoration mechanism",
        ],
        "device_actions_performed":False,
    }


def gotham_evidence_audit():
    return {
        "evidence_type":"2026_10_26_author_report_only_not_code_or_hardware_reproduced",
        "public_announcement":GOTHAM_POST,
        "linked_public_script":GOTHAM_GIST,
        "author_reported_ble_wifi_provisioning":True,
        "author_reported_connected_status":"0x3c",
        "author_reported_tls_handshake_followup":True,
        "python_gist_source_code_audited_in_this_phase":False,
        "independent_network_connection_reproduced":False,
        "public_gotham_device_key_field_handling_verified":False,
        "local_webrtc_gamepad_service_exists":False,
        "credential_input_or_storage":False,
        "next_validation":[
            "Fetch and verify published script bytes/revision through an accessible source",
            "Static audit of BLE characteristics, security and credential logging",
            "Model Wi-Fi provisioning offline with synthetic credentials only",
            "Analyze authenticated local protocol without impersonating Google services",
        ],
        "device_actions_performed":False,
    }


def audit(recovery_sources,phase81,phase83,phase86):
    return {
        "research_phase":90,
        "date":"2026-10-27",
        "recovery":recovery_source_audit(recovery_sources),
        "nxp_hab":hab_precondition_audit(phase81,phase83,phase86),
        "gotham_wifi":gotham_evidence_audit(),
        "recommendation":"GO_OFFLINE_PROTOCOL_AND_RECOVERY_MODEL; NO_GO_PHYSICAL_FLASH_OR_UNVERIFIED_HAB_BYPASS",
        "safe_only":True,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upstream-dir",type=Path,required=True,
                   help="Directory containing exact original public Gary sources, by repository paths")
    p.add_argument("--evidence-dir",type=Path,default=Path("evidence"))
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    sources={key:(args.upstream_dir/key).read_bytes() for key in UPSTREAM}
    ev=args.evidence_dir
    original=[json.loads((ev/name).read_text(encoding="utf-8")) for name in
              ("nxp-rom-csf-phase81.json","hab-rom-version-phase83.json",
               "bootloader-update-transaction-phase86.json")]
    result=audit(sources,*original)
    out=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(out,encoding="utf-8")
    else:
        print(out,end="")


if __name__=="__main__":
    main()
