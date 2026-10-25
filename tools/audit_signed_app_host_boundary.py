"""Reproducible, original-image-only Stadia app/updater execution-boundary audit.

Takes archived OEM update image and archived OEM host JavaScript as read-only
files. Verifies both exact identities; validates CMS signed blocks with the
repository verifier; classifies references into CSF/certificate/trailer
separately from code. Does not transmit packets, write flash, emulate
execution, or promise unauthenticated firmware support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools import audit_signed_app_surface as surface
from tools import audit_app_usb_dispatch as dispatch
from tools import audit_archived_updater as host
from tools import audit_final_auth_recovery as final
from tools.verify_hab import verify

SPEC = final.SAMPLES["bruce_signed_update"]
BASE = SPEC["base"]
IVT = SPEC["ivt_offset"]
CSF = SPEC["csf_offset"]
CSF_END = CSF + SPEC["csf_length"]
SIZE = SPEC["size"]
TRACKED_PARSERS = (
    ("HID tag-5 / rumble path", 0x18B64),
    ("HID callback registration", 0x18BDC),
    ("ITCM reception dispatcher stored", 0x29BC),
)
MODES = {"normal": "18d1:9400", "ROM_SDP": "1fc9:0135",
         "signed_RAM_loader": "15a2:0073", "bootloader": "18d1:946b"}


def classify_offset(offset):
    if not 0 <= offset < SIZE:
        raise ValueError("not within signed update file")
    if offset < IVT:
        return "authenticated_application_content"
    if offset < CSF:
        return "authenticated_ivt_prefix"
    if offset < CSF_END:
        return "csf_commands_not_part_of_application_signed_block"
    return "post_csf_signature_certificate_or_padding"


def static_tail_references(image):
    """Raw aligned words; xrefs are NOT proven instructions or viable calls."""
    if len(image) != SIZE:
        raise ValueError("wrong image size")
    candidates = []
    for offset in range(0, CSF, 4):
        value = struct.unpack_from("<I", image, offset)[0]
        candidate = value & ~1
        if BASE + CSF <= candidate < BASE + SIZE:
            candidates.append({
                "word_offset": hex(offset),
                "literal_pointer": hex(value),
                "target_file_offset": hex(candidate - BASE),
                "target_kind": classify_offset(candidate - BASE),
                "thumb_bit": bool(value & 1),
            })
    return candidates


def evaluate_boundaries(image, js, *, verifier=verify,
                        inspect_surface=surface.inspect,
                        inspect_dispatch=dispatch.inspect,
                        inspect_host=host.audit):
    if len(image) != SIZE or hashlib.sha256(image).hexdigest() != SPEC["sha256"]:
        raise ValueError("Bruce image does not match SHA-pinned owner sample")
    # Authenticated surface and host identities are independently checked.
    app = inspect_surface(image)
    usb = inspect_dispatch(image)
    host_result = inspect_host(js)
    result = verifier(image, BASE, CSF, ())
    signers = result["signatures"]
    if not signers or not all(s["rsa_signature_valid"] and s["digest_matches"]
                              for s in signers):
        raise ValueError("CMS signature or content digest not verified")
    blocks = [(int(b["file_offset"], 16), b["bytes"])
              for s in signers for b in s["blocks"] if b.get("type") != "CSF commands"]
    if blocks != [(0, CSF)]:
        raise ValueError("Authenticated application block coverage changed")
    if struct.unpack_from("<8I", image, IVT) != SPEC["ivt_expected"]:
        raise ValueError("Signed IVT differs")
    pointers = static_tail_references(image)
    # Only one *aligned* XIP pointer into the non-application-authenticated
    # zone appears in the actual signed payload: the IVT's expected CSF pointer.
    # This is an authentication metadata reference, NOT executable code.
    expected_csf_pointer = [{
        "word_offset": hex(IVT+0x18),
        "literal_pointer": hex(BASE+CSF),
        "target_file_offset": hex(CSF),
        "target_kind": classify_offset(CSF),
        "thumb_bit": False,
    }]
    if pointers != expected_csf_pointer:
        raise ValueError("Unexpected raw aligned references into post-signing section")
    labels = {
        "app_bytes": SIZE,
        "authenticated_application_block": CSF,
        "ivt_prefix_authenticated_bytes": CSF-IVT,
        "csf_command_bytes": CSF_END-CSF,
        "after_csf_bytes": SIZE-CSF_END,
        "not_in_application_signed_block_total_bytes": SIZE-CSF,
    }
    return {
        "date": "2026-10-25",
        "source_identification":{
            "public_archive_path":"StadiaMemories/firmware/bruce_pvt_a_prod_signed.bin",
            "matches_owner_private_sample_sha256":True,
            "image_sha256":SPEC["sha256"],
            "archived_host_js_exact_blob_checked":host_result["identity_verified"],
            "archived_host_source_sha1":host_result["source_git_blob_sha1"],
            "installed_device_byte_identity":"NOT VERIFIED — public image versus device not read back",
        },
        "auth":{
            "embedded_certificates_rsa_and_cms_checked":len(signers),
            "authenticated_block_file_span":["0x0",hex(CSF)],
            "fused_srk_hash_checked":False,
            "verified_by_device":"NOT TESTED",
            "ivt_pointer":hex(IVT),
            "csf_pointer":hex(CSF),
            "file_layout":labels,
            "trailer_not_covered_by_application_block_is_free_executable_memory":False,
            "tail_explanation":"CSF/certificates/signatures and possible padding have distinct semantics; an unsigned byte range is NOT an executable extension or HAB bypass",
        },
        "tail_xref_candidates":{
            "signed_region_aligned_word_matches":len(pointers),
            "static_candidates":pointers[:50],
            "all_candidates_truncated":len(pointers)>50,
            "only_static_candidate_is_ivt_csf_pointer":True,
            "evidence_level":"unaligned instructions and indirect or computed pointers may be missed; literal words are NOT verified executable references",
        },
        "app_receiver":{
            "static_tag5_role":app["parser_candidate"]["guard_classification"],
            "usb_dispatch":usb["static_receive_chain"]["invoke"],
            "known_handler":app["parser_candidate"]["entry"],
            "flash_update_or_arbitrary_execution":"NOT TRACED",
            "external_host_reachability":"NOT MEASURED",
        },
        "archived_host_update":{
            "device_modes":MODES,
            "host_normal_version_battery_only":True,
            "host_uses_rom_sdp_then_signed_ram_loader":True,
            "host_programs_with_signed_loader_and_verifies_build":True,
            "host_programs_via_bootloader_A_bulk":"NO in this archived script",
            "accepted_user_modified_unsigned_image":"NOT DEMONSTRATED",
            "host_file_metadata_not_equivalent_to_crypto_auth":True,
        },
        "decision":{
            "authenticated_custom_code":False,
            "safe_recovery_proved":False,
            "HAB_CLOSED_bypassed":False,
            "native_console_support":False,
            "next_research_gate":"Require a measured/reproduced host-to-code execution path with a reliable recovery method; source-level matches alone are insufficient",
        },
        "operations":{"controller_connected":False,"usb_packets":False,
                      "flash_writes":False,"efuse_writes":False,
                      "proprietary_binary_committed":False},
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("archived_js",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    report=evaluate_boundaries(args.bruce.read_bytes(),args.archived_js.read_bytes())
    doc=json.dumps(report,indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(doc,encoding="utf-8")
    else:
        print(doc,end="")


if __name__ == "__main__":
    main()
