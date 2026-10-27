"""Phase 89: offline Thumb-2 MOVW/MOVT provenance of SRC_GPR7 address builders.

A bounded halfword-aligned *encoding census* on exact SHA-256 checked OEM images.
No disassembly reachability, instruction-boundary proof, dataflow correctness,
USB linkage, device I/O, flash, OTP, or custom execution is claimed.

Consecutive MOVW/MOVT is a stronger static candidate than a wide-gap match,
but an encoding match in arbitrary image data may still be a false positive.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import audit as audit_original, SAMPLES
from tools.audit_src_gpr7_writers_phase88 import SRC_BASE, SRC_GPR6, SRC_GPR7

# Target only documented i.MX RT1060 SRC register constants.
LOW_HALVES = {0x8000: SRC_BASE, 0x8034: SRC_GPR6, 0x8038: SRC_GPR7}
HIGH_HALF = 0x400F
PAIR_WINDOW = 96
STORE_WINDOW = 96
MAX_ITEMS = 4096


def decode_thumb_mov_imm(image, offset):
    """Recognize one 32-bit Thumb MOVW/MOVT shape at the supplied halfword."""
    if not isinstance(image, bytes) or offset < 0 or offset % 2 or offset + 4 > len(image):
        return None
    hi, lo = struct.unpack_from("<HH", image, offset)
    tag = hi & 0xFBF0
    if tag not in (0xF240, 0xF2C0):
        return None
    kind = "movw" if tag == 0xF240 else "movt"
    reg = (lo >> 8) & 15
    # A PC target is invalid for MOVW/MOVT, reject here.
    if reg == 15:
        return None
    imm16 = ((hi & 15) << 12) | (((hi >> 10) & 1) << 11) | (((lo >> 12) & 7) << 8) | (lo & 0xFF)
    return {"offset":offset, "kind":kind, "reg":reg, "imm16":imm16,
            "hex":image[offset:offset+4].hex()}


def decode_thumb_store(image, offset):
    """Recognize STR word T1 or T3; no control-flow or register-value tracing."""
    if not isinstance(image, bytes) or offset < 0 or offset % 2 or offset+2 > len(image):
        return None
    h1=struct.unpack_from("<H",image,offset)[0]
    if (h1 & 0xF800) == 0x6000:  # STR (imm5 word-scale), 16-bit
        return {"offset":offset,"kind":"str_imm_t1",
                "base_reg":(h1>>3)&7,"value_reg":h1&7,
                "disp":((h1>>6)&31)*4,
                "bytes":image[offset:offset+2].hex()}
    if (h1 & 0xFFF0) == 0xF8C0 and offset+4 <= len(image):  # STR.W (imm12), 32-bit
        h2=struct.unpack_from("<H",image,offset+2)[0]
        return {"offset":offset,"kind":"str_imm_t3",
                "base_reg":h1&15,"value_reg":(h2>>12)&15,
                "disp":h2&4095,"bytes":image[offset:offset+4].hex()}
    return None


def analyze_encodings(image, stop, *, pair_window=PAIR_WINDOW, store_window=STORE_WINDOW):
    if not isinstance(image,bytes) or not 0 <= stop <= len(image):
        raise ValueError("Source image or CSF boundary invalid")
    if not 4 <= pair_window <= 256 or not 4 <= store_window <= 256:
        raise ValueError("Window must be between 4 and 256 bytes")

    movw=[];movt=[]
    for off in range(0,stop-3,2):
        ins=decode_thumb_mov_imm(image,off)
        if not ins:
            continue
        if ins["kind"]=="movw" and ins["imm16"] in LOW_HALVES:
            movw.append(ins)
        elif ins["kind"]=="movt" and ins["imm16"]==HIGH_HALF:
            movt.append(ins)
    if len(movw)+len(movt)>MAX_ITEMS:
        raise ValueError("Excessive constant synthesis candidates")
    pairs=[];str_candidates=[]
    for w in movw:
        for t in movt:
            delta=t["offset"]-w["offset"]
            if delta < 4 or delta > pair_window:
                continue
            if t["reg"] != w["reg"]:
                continue
            addr=(t["imm16"]<<16)|w["imm16"]
            item={"movw_offset":hex(w["offset"]),"movt_offset":hex(t["offset"]),
                  "movw_bytes":w["hex"],"movt_bytes":t["hex"],
                  "register":f"r{w['reg']}","computed_constant_if_same_live_register":f"0x{addr:08x}",
                  "movw_movt_adjacent":delta==4,
                  "actual_reaching_definition_proven":False,
                  "both_encodings_at_real_instruction_boundaries_proven":False}
            pairs.append(item)
            if len(pairs)>MAX_ITEMS:
                raise ValueError("Excessive matched constant builders")
            for at in range(t["offset"]+4,min(t["offset"]+4+store_window,stop-1),2):
                store=decode_thumb_store(image,at)
                if store and store["base_reg"]==w["reg"] and addr+store["disp"]==SRC_GPR7:
                    str_candidates.append({
                        "movw_offset":hex(w["offset"]),"movt_offset":hex(t["offset"]),
                        "possible_store_offset":hex(at),
                        "store_encoding":store["kind"],
                        "store_instruction_bytes":store["bytes"],
                        "possible_value_register":f"r{store['value_reg']}",
                        "possible_effective_address":f"0x{SRC_GPR7:08x}",
                        "runtime_store_proven":False,
                        "bit3_value_proven":False,
                        "host_usb_control_proven":False,
                    })
                if len(str_candidates)>MAX_ITEMS:
                    raise ValueError("Excessive candidate MMIO store patterns")
    return {
        "movw_low_half_encodings":len(movw),
        "movt_0x400f_encodings":len(movt),
        "movw_candidates":[{"file_offset":hex(x["offset"]),"reg":f"r{x['reg']}",
                            "imm16":f"0x{x['imm16']:04x}"} for x in movw],
        "movt_candidates":[{"file_offset":hex(x["offset"]),"reg":f"r{x['reg']}"} for x in movt],
        "same_register_ordered_pairs":pairs,
        "pair_count":len(pairs),
        "possibly_computed_gpr7_store_shapes":str_candidates,
        "store_shape_count":len(str_candidates),
        "confirmed_gpr7_bit3_writer_count":0,
        "bounds":{"pair_window_bytes":pair_window,"store_window_bytes":store_window,
                  "pre_csf_end_exclusive":hex(stop)},
        "negative_result_does_not_exclude_indirect_writers":True,
        "reason":"Thumb encoding matches can occur in data or in the middle of instructions; register clobber, calls, branches, literal loads, relocation and reachability are not resolved.",
    }


def audit(image, sample):
    verified=audit_original(image,sample)  # exact original SHA, IVT and CSF first
    findings=analyze_encodings(image,SAMPLES[sample]["csf"])
    return {"research_phase":89,"sample":sample,"original_sha256":verified["sample_sha256"],
            "questions":"Are any 0x400F8xxx SRC addresses synthesized via Thumb MOVW/MOVT and stored through directly?",
            **findings,
            "device_io":False,"physical_execution":False,"custom_firmware_execution":False,
            "private_bootloader_a_not_available_for_full_binary_scan":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--sample",choices=sorted(SAMPLES),required=True)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    result=audit(a.image.read_bytes(),a.sample)
    payload=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(payload,encoding="utf-8")
    else:
        print(payload,end="")


if __name__=="__main__":
    main()
