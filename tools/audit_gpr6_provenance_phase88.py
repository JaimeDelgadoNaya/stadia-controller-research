"""Phase 88: source-side GPR6 writer triage, strictly offline and bounded.

Question: do signed Bruce OEM data or selected bootloader-A disassembly
contain a *proven* writer of SRC_GPR6 update-request bit 3 (0x08)?
No hardware access, firmware changes, USB packets, or user-supplied inputs.

Raw 32-bit literal matches and nearby Thumb-load shapes are candidates only.
The source is not a full control-flow graph. A zero count does NOT prove
there are no MOVW/MOVT, computed-pointer, peripheral-alias or indirect writes.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import audit as audit_signed_bruce
from tools.audit_bootloader_update_trigger_phase87 import validate as validate_bootloader
from tools.audit_hab_rvt_literals_phase84 import thumb_pc_relative_ldr_candidates

GPR6 = 0x400F8038
GPR6_BASE = 0x400F8000
GPR6_OFFSET = 0x38
TARGETS = {GPR6_BASE:"src_register_block_base",GPR6:"src_gpr6_full_address"}
MAX_LITERAL_HITS = 4096
BRUCE_XIP_BASE = 0x60040000


def census_bruce_literals(image):
    """Scan signed image only through CSF start, after whole-image SHA gate."""
    prior = audit_signed_bruce(image, "bruce_prod")
    stop = 0xff030
    if stop > len(image):
        raise ValueError("Signed Bruce image shorter than expected code span")
    hits = []
    for at in range(0, stop-3, 2):
        value=struct.unpack_from("<I",image,at)[0]
        if value not in TARGETS:
            continue
        refs=thumb_pc_relative_ldr_candidates(image,at,lookback=1100)
        hits.append({
            "file_offset":hex(at),
            "mapped_xip_address":hex(BRUCE_XIP_BASE+at),
            "constant":f"0x{value:08x}",
            "role":TARGETS[value],
            "alignment":"word" if at%4==0 else "halfword",
            "syntactic_thumb_load_candidates":refs,
            "verified_instruction_use":False,
            "proven_gpr6_bit3_writer":False,
        })
        if len(hits)>MAX_LITERAL_HITS:
            raise ValueError("Unexpected number of literal candidates")
    return {
       "original_image_sha256":prior["sample_sha256"],
       "scan_end_exclusive":hex(stop),
       "literal_hits":hits,
       "literal_counts":{
           "src_register_block_base":sum(x["role"]=="src_register_block_base" for x in hits),
           "src_gpr6_full_address":sum(x["role"]=="src_gpr6_full_address" for x in hits),
       },
       "confirmed_writers_of_gpr6_bit3":0,
       "signed_bruce_xip_to_bootloader_trigger_proven":False,
       "meaning":"Raw original words only; not a complete search of computed SRC addresses."
    }


def _hex(value):
    return int(value,16)


def census_bootloader_selected(records):
    """Classify only GPR6 accesses in pinned *selected* original instructions."""
    ins=validate_bootloader(records)  # phase87 + earlier hash-labeled opcodes
    # Capture unambiguous pinned sites, not any same-shape STR with unknown base.
    definite = [
        {
          "address":"0x60802866","kind":"read_snapshot",
          "effective_address":"0x400f8038","effect":"read_existing_flags",
          "sets_update_bit3":False
        },
        {
          "address":"0x6080286a","kind":"write_clear",
          "effective_address":"0x400f8038","value":"0x00",
          "sets_update_bit3":False
        },
        {
          "address":"0x60801f14","kind":"write_status_on_app_failure",
          "effective_address":"0x400f8038","values":["0x10","0x20"],
          "sets_update_bit3":False
        },
    ]
    store_shapes=[]
    other_literal_sources=[]
    for i in sorted(ins.values(),key=lambda x:_hex(x["address"])):
        if i["mnemonic"].lower().startswith("str") and (
                "#0x38]" in i["operands"] or
                "#0x38," in i["operands"]):
            store_shapes.append({
                "site":i["address"], "mnemonic":i["mnemonic"],
                "operands":i["operands"],
                "real_target_gpr6_proven":i["address"] in
                     ("0x6080286a","0x60801f14"),
            })
        if i.get("literal_uint32","").lower() in ("0x400f8000","0x400f8038"):
            other_literal_sources.append({
                "site":i["address"],
                "constant":i["literal_uint32"].lower()
            })
    return {
      "original_record_sha256_label":records["sha256"],
      "private_bootloader_binary_rehashed_now":False,
      "selected_original_instruction_count":len(ins),
      "pinned_gpr6_accesses":definite,
      "all_selected_str_offset_0x38_shapes":store_shapes,
      "selected_literal_sources":other_literal_sources,
      "unambiguous_selected_bit3_setters":0,
      "complete_bootloader_writer_census":False,
      "candidate_reset_persistence":"NOT_MEASURED",
      "host_usb_writer_proven":False,
      "meaning":"Only published disassembly regions; all unexamined bootloader code remains unknown."
    }


def audit(bruce, records):
    return {
       "phase":88,
       "research_question":"Who produces SRC_GPR6 bit3 (update request 0x08)?",
       "bruce_signed_original":census_bruce_literals(bruce),
       "bootloader_selected_original":census_bootloader_selected(records),
       "decision":"NO_HOST_CONTROL_CLAIM_WITHOUT_PROVEN_GPR6_BIT3_WRITER",
       "caveats":[
          "Positive raw constants are not instructions or proof of a GPR6 write.",
          "Negative literal census cannot rule out calculated, relocated or indirectly loaded addresses.",
          "Selected bootloader disassembly covers only portions of 131072-byte image.",
          "The bootloader's GPR6 clear and app-error writers do not set the update bit.",
          "Signed Bruce archived update image is not hash-matched to the installed controller.",
          "No runtime SRC register read, USB request, bootloader update, flash write or OTP change.",
          "No HAB CLOSED bypass or signed-code execution proven.",
       ],
       "device_connected":False,
       "firmware_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path,help="Local original signed Bruce update (exact pinned hash)")
    p.add_argument("--boot-record",type=Path,
                   default=Path("evidence/bootloader-analysis.json"))
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    r=audit(a.bruce.read_bytes(),json.loads(a.boot_record.read_text(encoding="utf-8")))
    result=json.dumps(r,indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(result,encoding="utf-8")
    else:
        print(result,end="")


if __name__=="__main__":
    main()
