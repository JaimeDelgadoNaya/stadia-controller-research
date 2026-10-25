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
    targets={}
    for state,target in USB1_BRANCH_ARMS.items():
        targets[str(state)]={
            "target":hex(target),
            "target_kind":categorize(target|1),
            "code_preview":disassemble_candidate(image,target|1,span=208)[:65],
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
    for state,arm in result["USB_OTG1_mode_dispatch"]["branch_arms"].items():
        print("USB1_MODE",state,"TARGET",arm["target"])
        for ins in arm["code_preview"]:
            print(ins["pc"],ins["m"],ins["op"])
    print("EP0 callback established? No (vector and mode arms are static only).")


if __name__=="__main__":
    main()
