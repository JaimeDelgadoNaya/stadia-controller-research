"""SHA-pinned signed Bruce vector-table origin of i.MX RT1060 USB IRQs.

USB_OTG2_IRQn=112 and USB_OTG1_IRQn=113 per NXP RT1060 reference manual.
A flash-table vector identifies a *candidate* IRQ wrapper only. Whether the
running firmware uses that vector table (SCB->VTOR) and whether the wrapper
reaches class EP0 SETUP dispatch are separate questions.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

IRQS={"USB_OTG2":112,"USB_OTG1":113}
# Two direct tail branches in the hash-pinned OTG1 wrapper. Not proof that
# either branch has been taken in a live board.
EP0_SETUP_HELPER=0xBA68
USB1_BRANCH_ARMS={
    2:0x6013D1F8,
    3:0x600D546A,
}
VECTOR_BASE=ASSUMED_XIP_BASE
VECTOR_STRIDE=4
CORE_EXCEPTIONS=16


def categorize(vector):
    addr=vector & ~1
    if not (vector & 1):
        return "non_thumb_or_null"
    if ASSUMED_XIP_BASE <= addr < ASSUMED_XIP_BASE+0xFF000:
        return "signed_flash_XIP"
    if 0 <= addr < ITCM_LENGTH:
        return "startup_relocated_ITCM_candidate"
    if 0x20000000 <= addr < 0x20040000:
        return "RAM_pointer_unverified"
    return "outside_known_app_regions"


def byte_offset_for_handler(vector):
    kind=categorize(vector)
    if kind=="signed_flash_XIP":
        return (vector & ~1)-ASSUMED_XIP_BASE
    if kind=="startup_relocated_ITCM_candidate":
        return ITCM_SOURCE_OFFSET+(vector & ~1)
    return None


def disassemble_candidate(image, vector, span=112):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    off=byte_offset_for_handler(vector)
    if off is None:
        return []
    end=min(off+span,0xFF000)
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    pc=vector & ~1
    return [{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str}
            for i in dec.disasm(image[off:end],pc)]


def resolve_ldr_pc_veneer(image, source):
    """Resolve a PC-relative Thumb LDR trampoline; literal bytes are not code."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    pos=source-VECTOR_BASE
    if pos < 0 or pos+8 > len(image):
        raise ValueError("veneer outside original image")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    ins=next(iter(md.disasm(image[pos:pos+4],source,count=1)),None)
    if not ins or ins.mnemonic!="ldr.w" or ins.op_str.replace(" ","")!="pc,[pc,#-0x0]":
        raise ValueError("original PC-relative veneer opcode differs")
    literal_addr=(source+4)&~3
    target=struct.unpack_from('<I',image,literal_addr-VECTOR_BASE)[0]
    all_code=disassemble_candidate(image,target,span=0x1d0)
    reg_terms=("#0x1ac", "#0x1bc", "#0x1b8", "#0x1b0", "#0x144", "#0x148")
    high=[]
    for idx,row in enumerate(all_code):
        if any(term in row["op"] for term in reg_terms):
            high.append({
                "pc":row["pc"],"ins":row["m"]+" "+row["op"],
                "context":all_code[max(0,idx-3):min(len(all_code),idx+5)],
            })
    return {
        "veneer_pc":hex(source),
        "literal_address":hex(literal_addr),
        "target_pointer":hex(target),
        "target_classification":categorize(target),
        "target_file_offset":hex(byte_offset_for_handler(target)) if byte_offset_for_handler(target) is not None else None,
        "target_code_preview":all_code[:65],
        "ITCM_candidate_USB_register_accesses":high,
        "ITCM_candidate_disassembly_len":len(all_code),
        "ITCM_setup_status_path_window":[row for row in all_code
            if 0x11B4 <= int(row["pc"],16) < 0x1278],
        "runtime_executed":"UNVERIFIED",
    }

EP0_RECEIVER_ANCHORS = {
    0x600D0FCA: ("ldrb", "r2, [r1, #8]"),
    0x600D1010: ("and", "r3, r2, #0xf"),
    0x600D1014: ("cmp", "r3, #7"),
    0x600D1018: ("lsls", "r3, r3, #1"),
    0x600D101A: ("orr.w", "r3, r3, r2, lsr #7"),
    0x600D1020: ("mla", "r2, r2, r3, r0"),
    0x600D1024: ("ldr", "r0, [r2, #0xc]"),
    0x600D1028: ("ldr", "r0, [r1]"),
    0x600D102C: ("ldr", "r0, [r1, #4]"),
    0x600D104A: ("ldrd", "r5, r2, [r3, #0xc]"),
    0x600D104E: ("blx", "r5"),
}

def check_setup_dispatch_anchors(decoded):
    for pc, expected in EP0_RECEIVER_ANCHORS.items():
        if decoded.get(pc)!=expected:
            raise ValueError("Original EP0 callback dispatch semantic drift at "+hex(pc))
    return True

def inspect(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed Bruce image size and SHA-256 required")
    rows=[]
    for label,irq in IRQS.items():
        word_index=CORE_EXCEPTIONS+irq
        off=word_index*VECTOR_STRIDE
        entry=struct.unpack_from("<I",image,off)[0]
        rows.append({
            "peripheral":label,
            "nvic_irq_number":irq,
            "cortex_m_exception_slot":word_index,
            "vector_file_offset":hex(off),
            "signed_image_vector":hex(entry),
            "vector_classification":categorize(entry),
            "handler_source_file_offset": (
                hex(byte_offset_for_handler(entry))
                if byte_offset_for_handler(entry) is not None else None),
            "handler_disassembly_preview":disassemble_candidate(image,entry),
            "live_SCB_VTOR_matches_image_vector_table":"UNVERIFIED",
            "handler_connected_to_EP0_setup_callback":"UNVERIFIED",
        })
    veneer=resolve_ldr_pc_veneer(image,USB1_BRANCH_ARMS[2])
    setup_helper_preview=disassemble_candidate(image,EP0_SETUP_HELPER|1,span=110)
    setup_helper_raw_literal=struct.unpack_from("<I",image,
                ITCM_SOURCE_OFFSET+EP0_SETUP_HELPER+4)[0]
    if setup_helper_raw_literal != 0x600D0FB7:
        raise ValueError("Pinned original SETUP handler veneer target differs")
    setup_receiver_disassembly=disassemble_candidate(image,setup_helper_raw_literal,span=360)[:135]
    check_setup_dispatch_anchors({
        int(ins["pc"],16):(ins["m"],ins["op"]) for ins in setup_receiver_disassembly
    })
    targets={}
    for state,target in USB1_BRANCH_ARMS.items():
        targets[str(state)]={
            "target":hex(target),
            "target_kind":categorize(target|1),
            "code_preview":disassemble_candidate(image,target|1,span=208)[:65] if state!=2 else [],
            "live_reachability":"UNVERIFIED",
            "EP0_effect":"UNVERIFIED",
        }
    return {
        "original_bruce_sha256":IMAGE_SHA256,
        "image_validated":True,
        "assumption":"Standard Cortex-M vector at signed image start. Running VTOR may be relocated; this is NOT a live register measurement.",
        "vectors":rows,
        "USB_OTG1_mode_dispatch":{
            "entry":"0x600610d0",
            "selector":"global structure at +0x3e78 (runtime RAM state not measured)",
            "mode_2_branch":"0x6013d1f8",
            "mode_3_branch":"0x600d546a",
            "branch_arms":targets,
            "mode_2_LDR_PC_veneer":veneer,
            "EP0_SETUP_candidate":{
                "callsite_in_copied_ITCM":"0x1258",
                "callsite_direct_target":"0xba68",
                "before_call":"USB ENDPTSETUPSTAT bit loop copies controller SETUP data",
                "helper_code":setup_helper_preview,
                "helper_word_after_entry":hex(setup_helper_raw_literal),
                "resolved_signed_xip_receiver":"0x600d0fb6",
                "receiver_code_preview":setup_receiver_disassembly,
                "callback_slot_index":"2*(endpoint & 0x0F) + ((endpoint >> 7) & 1)",
                "callback_slot_stride_bytes":12,
                "callback_is_taken_from_runtime_object":True,
                "callback_dispatch_pc":"0x600d104e",
                "callback_pointer_at_rest":"UNRESOLVED: runtime endpoint slot",
                "direct_callback_reached_from_signed_code":"CONDITIONAL on status and registered slot",
                "handler_callback_after_helper":"DYNAMIC callback slot confirmed; actual endpoint-0 receiver pointer unknown",
                "host_bRequest_0x81_0x83_0x84_effect":"UNVERIFIED",
            },
            "condition_code":"observed CMP #2/#3 and conditional branches; no physical mode state captured",
        },
        "USB_to_EP0_proof":False,
        "host_control_request_receivers_identified":False,
        "unsafe_device_ops":False
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bruce",type=Path)
    ap.add_argument("--out",type=Path)
    a=ap.parse_args()
    result=inspect(a.bruce.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    for row in result["vectors"]:
        print("IRQ",row["peripheral"],row["nvic_irq_number"],
              "vector",row["signed_image_vector"],
              "kind",row["vector_classification"],
              "file",row["handler_source_file_offset"])
        for i in row["handler_disassembly_preview"][:32]:
            print(i["pc"],i["m"],i["op"])
    v=result["USB_OTG1_mode_dispatch"]["mode_2_LDR_PC_veneer"]
    print("USB1_MODE_2_VENEER",v["veneer_pc"],v["literal_address"],v["target_pointer"],v["target_classification"],v["target_file_offset"])
    for ins in v["target_code_preview"][:42]:
        print("USB1_VENEER_TARGET",ins["pc"],ins["m"],ins["op"])
    print("USB1 ITCM register candidates:",v["ITCM_candidate_USB_register_accesses"])
    helper=result["USB_OTG1_mode_dispatch"]["EP0_SETUP_candidate"]
    print("EP0_HELPER",helper["callsite_direct_target"],"raw next word",helper["helper_word_after_entry"])
    for ins in helper["helper_code"][:45]:
        print("EP0_HELPER_CODE",ins["pc"],ins["m"],ins["op"])
    print("EP0_RECEIVER",helper["resolved_signed_xip_receiver"])
    for ins in helper["receiver_code_preview"][:70]:
        print("EP0_RECEIVER_CODE",ins["pc"],ins["m"],ins["op"])
    for state,arm in result["USB_OTG1_mode_dispatch"]["branch_arms"].items():
        print("USB1_MODE",state,"TARGET",arm["target"])
        for ins in arm["code_preview"]:
            print(ins["pc"],ins["m"],ins["op"])
    print("EP0 callback established? No (vector and mode arms are static only).")


if __name__=="__main__":
    main()
