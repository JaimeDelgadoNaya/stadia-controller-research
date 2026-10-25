"""Phase 31: final read-only authentication/recovery decision gate.

Use the owner's matching *private* bootloader A and Bruce signed application.
This invokes the repository's existing offline HAB/CMS signature verifier
(tools/verify_hab.py). It verifies digests and RSA signatures using embedded
certificates but CANNOT read fused SRK trust, prove installed-flash identity,
try arbitrary code on hardware, or guarantee recovery.

No WebUSB/WebHID, flash, eFuse, programming or device operations occur.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from .verify_hab import verify as verify_hab
except ImportError:
    from verify_hab import verify as verify_hab

SAMPLES = {
    "bootloader_a": {
        "size": 131072,
        "sha256": "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0",
        "base": 0x60800000, "ivt_offset": 0,
        "ivt_expected": (0x412000D1, 0x60801000, 0, 0, 0x60001020, 0x60001000, 0x60818000, 0),
        "csf_offset": 0x18000, "csf_length": 0x60,
        "aliases": ((0x60001000, 0, 0x1000),),
        "signed_expected": (
            (0x60001000, 0, 0x1000),
            (0x60800000, 0, 0x18000),
        ),
        "code_fingerprints": {
            "hab_wrapper": (0x1F5C, 0x1FA4, "c0a71ede67f348976e91f1795ff2718420306dbbf2b0111f5db8639e206618cd"),
            "app_validator": (0x200C, 0x2068, "59ebd74043303851dcb85ef7dc09563a2605c89ec9a4cdd96e8b1b91b673ddd7"),
            "app_jump": (0x1EF0, 0x1F5C, "edced003e3c9b8bad25f0b9cbec5ce10c45fe4c3b7a3c4a8952f01781c62cd7f"),
            "update_validation": (0x20A8, 0x2170, "b4f25540483bc803eae1cb8a73ee55063d63edf61d67bc5b4725a5d57f94e3f3"),
        },
        "identity_limit":"Owner-read actual persistent bootloader A; backup slot B reported erased",
    },
    "bruce_signed_update": {
        "size": 1050984,
        "sha256": "466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3",
        "base": 0x60040000, "ivt_offset": 0xFF000,
        "ivt_expected": (0x412000D1, 0x60040000, 0, 0, 0x6013F020, 0x6013F000, 0x6013F030, 0),
        "csf_offset": 0xFF030, "csf_length": 0x48,
        "aliases": (),
        "signed_expected": ((0x60040000, 0, 0xFF030),),
        "code_fingerprints": {
            "ivt": (0xFF000,0xFF030,"f6c0a147fd901ba0875e4f549e328e7a2c09f1a84678710e15094ad9ac1a533d"),
            "csf_header":(0xFF030,0xFF078,"e9e09fa78a4e3421928e6c5eb30b44c3bad23a0f9935f8ac2b10fc91ad13931a"),
        },
        "identity_limit":"Signed Bluetooth UPDATE IMAGE; not a separately verified complete installed flash dump",
    },
}

def hash_verified(data, expected_sha):
    if not isinstance(data,bytes):
        raise TypeError("Input must be bytes")
    digest=hashlib.sha256(data).hexdigest()
    if digest!=expected_sha:
        raise ValueError("Whole-image SHA-256 mismatch")
    return digest

def decode_layout(data, sample):
    """Structural bounds and IVT/CSF pointers only; no signature assertion."""
    if len(data)!=sample["size"]:
        raise ValueError("Unexpected image length")
    at=sample["ivt_offset"]
    if at+32>len(data):
        raise ValueError("IVT outside image")
    ivt=struct.unpack_from("<8I",data,at)
    if ivt!=sample["ivt_expected"]:
        raise ValueError("Unexpected image vector table")
    off=sample["csf_offset"]
    if off+sample["csf_length"]>len(data):
        raise ValueError("CSF outside image")
    csf=data[off:off+4]
    if csf[0]!=0xD4 or int.from_bytes(csf[1:3],"big")!=sample["csf_length"] or csf[3]!=0x42:
        raise ValueError("Unexpected CSF header")
    for name,(start,end,digest) in sample["code_fingerprints"].items():
        if not 0<=start<end<=len(data) or hashlib.sha256(data[start:end]).hexdigest()!=digest:
            raise ValueError(f"Code fingerprint mismatch: {name}")
    return {
        "ivt_file_offset":f"0x{at:x}","ivt_header":f"0x{ivt[0]:08x}",
        "ivt_entry":f"0x{ivt[1]:08x}","ivt_self":f"0x{ivt[5]:08x}",
        "ivt_csf_pointer":f"0x{ivt[6]:08x}",
        "csf_file_offset":f"0x{off:x}",
        "csf_command_length":sample["csf_length"],
        "ivt_source_coordinates":"The bootloader's 0x60001000 shared IVT is an explicit file-offset alias, not its extracted 0x60800000 slot"
            if sample["ivt_offset"]==0 else "Bruce CSF lives at image offset 0xFF030",
    }

def decision_gate(
    host_protocol_verified,
    executable_custom_code_authenticated,
    device_receiver_reachable,
    reliable_recovery_verified,
):
    """Finite-budget STOP/GO: all gates mandatory; no score or speculative override."""
    reasons={
        "host_protocol_verified":bool(host_protocol_verified),
        "device_receiver_reachable":bool(device_receiver_reachable),
        "executable_custom_code_authenticated":bool(executable_custom_code_authenticated),
        "reliable_recovery_verified":bool(reliable_recovery_verified),
    }
    return {
        "decision":"CONTINUE_INTERNAL" if all(reasons.values()) else "STOP_INTERNAL__START_EXTERNAL_BRIDGE",
        "gates":reasons,
        "unproven_requirements":[k for k,v in reasons.items() if not v],
        "no_further_open_ended_pointer_phases":True,
    }

def audit(bootloader, application):
    sources={"bootloader_a":bootloader,"bruce_signed_update":application}
    output={}
    for name,data in sources.items():
        sample=SAMPLES[name]
        if len(data)!=sample["size"]:
            raise ValueError(f"Wrong {name} size")
        digest=hash_verified(data,sample["sha256"])
        layout=decode_layout(data,sample)
        signatures=verify_hab(data,sample["base"],sample["csf_offset"],
                              sample["aliases"])
        actual=[]
        for signature in signatures["signatures"]:
            if not signature["digest_matches"] or not signature["rsa_signature_valid"]:
                raise ValueError(f"Failed CMS verification: {name}")
            for block in signature["blocks"]:
                if block.get("type")=="CSF commands":
                    continue
                actual.append((int(block["address"],16),int(block["file_offset"],16),block["bytes"]))
        if tuple(actual)!=sample["signed_expected"]:
            raise ValueError(f"Authenticated block coverage mismatch: {name}")
        output[name]={
            "sha256_verified":True,"sha256":digest,
            "size_bytes":len(data),"layout":layout,
            "rsa_signatures_valid":len(signatures["signatures"]),
            "signed_data_blocks":[
                {"address":f"0x{a:08x}","file_offset":f"0x{o:x}","bytes":n}
                for a,o,n in actual],
            "fused_SRK_trust_verified":False,
            "identity_limit":sample["identity_limit"],
        }
    gate=decision_gate(
        host_protocol_verified=True, # archived code and physical mode measurements
        device_receiver_reachable=True, # ROM + signed flashloader observed, not app parser
        executable_custom_code_authenticated=False, # none demonstrated
        reliable_recovery_verified=False, # no tested fallback/rollback
    )
    return {
        "phase":31,"package":"B FINAL",
        "operations":{"read_only":True,"connected_hardware":False,"usb_io":False,
                      "flash_write":False,"efuse_write":False},
        "images":output,
        "hab_closed_evidence":"ROM ERROR_STATUS 0x12343412 and restricted flashloader CFG5 bit1=1 on owner's tested unit; see docs/es/mediciones.md",
        "bootloader_validation_path":{
            "validator":"0x6080200c",
            "HAB_entry_wrapper":"0x60801f5c (ROM HAB RVT entry/authenticate_image_no_dcd/exit)",
            "authentication_before_application_jump":"0x60801f00 -> 0x6080200c; successful path jumps at 0x60801f46",
            "structural_update_check":"0x608020a8 with flag 0 possible",
            "post_update_auth_check":"0x608020a8 with flag 1, delegates to 0x60801f5c",
            "interpretation":"A structural pre-check is NOT signature authorization; the actual boot path authenticates",
            "scope":"bounded exact code fingerprint verification, existing phase-9 control flow; no arbitrary execution tested",
        },
        "recovery":{
            "ROM_SDP_entered_previously":True,
            "Google_signed_RAM_loader_accepted_previously":True,
            "bootloader_B_slot":"erased/all 0xFF on the tested unit",
            "full_application_installed_backup":"NOT AVAILABLE",
            "power_loss_restore_test":"NOT PERFORMED",
            "verified_custom_image_rollback":"NO",
            "automatic_fallback_or_recovery":"NOT DEMONSTRATED",
        },
        "executability":{
            "signed_google_images_accepted_in_known_flow":"YES for previously tested original RAM loader; Bruce update sample was verified offline, not flashed",
            "custom_image_signed_by_trusted_key":"NOT AVAILABLE/NOT DEMONSTRATED",
            "unsigned_custom_code_execution":"NOT DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
            "image_signature_verification":"VALID using embedded certificates; DOES NOT verify fused SRK trust",
        },
        "decision_gate":gate,
        "recommendation":"STOP further internal flashing/custom firmware research under agreed finite budget; proceed with reversible external Stadia->Xbox bridge feasibility, respecting authorized console authentication.",
        "bridge_constraints":"PC XInput USB emulation does not demonstrate Xbox One/Series console compatibility.",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Owner-extracted private bootloader A")
    p.add_argument("bruce",type=Path,help="Private signed Bruce update image")
    p.add_argument("--out",type=Path,help="Local-only sanitized JSON")
    args=p.parse_args()
    report=json.dumps(audit(args.bootloader.read_bytes(),args.bruce.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(report,encoding="utf-8")
    else:
        print(report,end="")

if __name__=="__main__":
    main()
