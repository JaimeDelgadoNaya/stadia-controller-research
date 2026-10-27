"""Phase 88: ROM-reserved SRC_GPR7 bit-3 writer provenance, offline only.

Corrects phase87's GPR6 misnomer (0x400F8038 is GPR7, not GPR6).
Two distinct evidence tiers:
- The existing selected original bootloader A Thumb corpus: known direct writes.
- Hash-pinned public OEM images: RAW constant words, NOT call/writer proofs.

No USB, SDP, flash, ROM calls or OTP/OCOTP actions. Never infer absence
of unexamined writers from a selected-instruction corpus.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_bootloader_update_trigger_phase87 import validate as pin_phase87
from tools.audit_nxp_rom_advisories_phase81 import SAMPLES, audit as pin_phase81
from tools.audit_hab_rvt_literals_phase84 import thumb_pc_relative_ldr_candidates

SRC_BASE = 0x400F8000
SRC_GPR6 = SRC_BASE + 0x34  # NXP i.MX RT1060 RM Rev 3 §21.6.10
SRC_GPR7 = SRC_BASE + 0x38  # NXP i.MX RT1060 RM Rev 3 §21.6.11
UPDATE_BIT = 0x08
IMAGE_CONSTANTS = {
    SRC_BASE: "src_base",
    SRC_GPR6: "src_gpr6_distinct_register",
    SRC_GPR7: "src_gpr7",
}
MAX_MATCHES = 4096


def selected_bootloader_writers(corpus):
    """Enumerate all *directly attributable* SRC_GPR7 writes within 903 selected instructions.

    We pin source opcode bytes to phase87's checks, then verify that the
    same function loads exact SRC_BASE into r3 before STR [r3,#0x38].
    The result is NOT a whole bootloader scan.
    """
    pin_phase87(corpus)
    functions = corpus["functions"]
    reads = []
    stores = []
    total_instr = 0
    for f in functions:
        instrs = f["instructions"]
        total_instr += len(instrs)
        base_at = None
        for ins in instrs:
            if (ins.get("literal_uint32") or "").lower() == f"0x{SRC_BASE:08x}" and (
                ins["mnemonic"] == "ldr" and ins["operands"].startswith("r3, [pc,")
            ):
                base_at = ins["address"]
                reads.append({"site":base_at, "literal":f"0x{SRC_BASE:08x}",
                              "register":"r3"})
                continue
            # Kill attribution if there is an intervening assignment to r3.
            if ins["mnemonic"] in ("str","str.w") and ins["operands"] == "r2, [r3, #0x38]":
                if base_at is not None:
                    address = int(ins["address"],16)
                    cls = {
                        0x6080286A: ("clear", ["0x00"], False),
                        0x60801F14: ("application_validation_status", ["0x10","0x20"], False),
                    }
                    meaning, values, sets = cls.get(address,("unknown_value",[],None))
                    stores.append({
                        "site":ins["address"],
                        "base_literal_load":base_at,
                        "destination":f"0x{SRC_GPR7:08x}",
                        "opcode_bytes":ins["bytes"],
                        "classification":meaning,
                        "values_in_pinned_local_path":values,
                        "sets_update_bit3":sets,
                        "direct_mmio_store_in_selected_corpus":True,
                    })
                continue
            if base_at is not None:
                # Conservative r3 overwrite detection; simple selected-corpus
                # tracking, not whole-function symbolic execution.
                token = ins["operands"].split(",")[0].strip()
                writes_register = (
                    ins["mnemonic"].startswith(("ldr", "mov", "add", "sub", "mul",
                                                 "and", "orr", "eor", "bic"))
                    or ins["mnemonic"] in ("pop", "ldm", "ldm.w")
                )
                if token == "r3" and writes_register:
                    base_at = None
    known = {int(x["site"],16) for x in stores}
    if known != {0x60801F14, 0x6080286A}:
        raise ValueError("Pinned selected-corpus GPR7 writer inventory changed")
    if len(reads) != 2:
        raise ValueError("Unexpected selected SRC base literal count")
    return {
        "source_type":"selected_original_thumb_disassembly_only",
        "published_original_sha256":corpus["sha256"],
        "complete_binary_available_or_rehashed":False,
        "selected_functions":len(functions),
        "selected_instructions":total_instr,
        "src_base_literal_loads":reads,
        "directly_attributed_gpr7_stores":sorted(stores,key=lambda x:int(x["site"],16)),
        "direct_store_count":len(stores),
        "known_selected_stores_setting_bit3":0,
        "complete_binary_writer_census":False,
        "indirect_or_calculated_writes_excluded":False,
        "rom_internal_writers_included":False,
    }


def raw_src_constant_census(image, boundary):
    """Scan exact 32-bit words at halfword offsets; never infer code references."""
    if not isinstance(image, bytes) or not 0 <= boundary <= len(image):
        raise ValueError("Invalid source bytes or pre-CSF boundary")
    hits=[]
    for at in range(0,boundary-3,2):
        word=struct.unpack_from("<I",image,at)[0]
        if word in IMAGE_CONSTANTS:
            hits.append({
                "file_offset":hex(at),
                "word":f"0x{word:08x}",
                "name":IMAGE_CONSTANTS[word],
                "alignment":"word_aligned" if at%4==0 else "halfword_only",
                "writer_reachable_or_executed":False,
                "instruction_xref_proven":False,
                "syntactic_thumb_pc_ldr_candidates":thumb_pc_relative_ldr_candidates(image,at),
            })
            if len(hits)>MAX_MATCHES:
                raise ValueError("Excessive SRC literal matches")
    return hits


def audit_public_original(image,sample):
    pinned=pin_phase81(image,sample)
    end=SAMPLES[sample]["csf"]
    hits=raw_src_constant_census(image,end)
    return {
        "sample":sample,
        "sha256_verified_whole_original":pinned["sample_sha256"],
        "pre_csf_boundary":hex(end),
        "raw_constant_hits":hits,
        "raw_hit_count":len(hits),
        "counts_by_name":{name:sum(h["name"]==name for h in hits)
                          for name in IMAGE_CONSTANTS.values()},
        "proven_direct_gpr7_writers":0,
        "proven_rom_or_usb_trigger_sources":0,
        "negative_count_proves_absence":False,
    }


def audit_selected(corpus):
    selected=selected_bootloader_writers(corpus)
    return {
        "phase":88,
        "finding":"Correction: 0x400F8038 is SRC_GPR7; phase87 used GPR6 in error.",
        "nxp_register_map":{
            "src_base":f"0x{SRC_BASE:08x}",
            "gpr6":f"0x{SRC_GPR6:08x}",
            "gpr7":f"0x{SRC_GPR7:08x}",
            "gpr7_rom_reserved_in_reference_manual":True,
            "gpr7_documented_reset_value":"0x00000000",
            "firmware_update_bit3_meaning":"GOOGLE_SIGNED_OEM_BRANCH_NOT_NXP_DEFINED_BIT",
        },
        "selected_bootloader_a":selected,
        "open_questions":{
            "who_sets_gpr7_bit3":"UNKNOWN",
            "rom_writes_gpr7_bit3":"NOT_DEMONSTRATED",
            "bruce_writes_gpr7_bit3":"NOT_DEMONSTRATED",
            "usb_control_of_bit3":"NOT_DEMONSTRATED",
            "warm_reset_persistence_on_controller":"NOT_MEASURED",
            "installed_firmware_execution":"NOT_DEMONSTRATED",
        },
        "decision":"PROVISIONAL_NO_GO_HOST_TRIGGER; GO_OFFLINE_FOR_PROVEN_WRITER_OR_SAFE_ROM_EVIDENCE",
        "safety":"Offline only; no hardware I/O, memory or fuse writes",
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bootloader-evidence",type=Path,default=Path(__file__).resolve().parents[1]/"evidence/bootloader-analysis.json")
    ap.add_argument("--public-image",type=Path)
    ap.add_argument("--sample",choices=("bruce_prod","restricted_ram_loader"))
    ap.add_argument("--out",type=Path)
    a=ap.parse_args()
    result=audit_selected(json.loads(a.bootloader_evidence.read_text(encoding="utf-8")))
    if a.public_image or a.sample:
        if not a.public_image or not a.sample:
            ap.error("--public-image and --sample must be supplied together")
        result["public_original"]=audit_public_original(a.public_image.read_bytes(),a.sample)
    output=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")


if __name__=="__main__":
    main()
