"""Phase 87: bounded OEM GPR6 bit-3 -> bootloader A update entry provenance.

Uses selected disassembly records previously extracted from owner bootloader A,
not a raw firmware image. No real hardware, USB or flash interaction.
"""
import argparse
import json
from pathlib import Path

from tools.audit_bootloader_update_transaction_phase86 import validate_corpus

BASE = 0x400F8000
REGISTER = BASE + 0x38
UPDATE_MASK = 0x08
CONTEXT_BASE = 0x200090D8
STORAGE_OBJECT = CONTEXT_BASE + 0x4D0
CALLBACK_THUMB = 0x6080285D
UPDATE_WRAPPER = 0x60801ED0
UPDATE_COORDINATOR = 0x60801DD4

# Exact address, Thumb bytes, instruction and operands. Original literals and
# BL destinations are pinned independently below.
PINS = (
    (0x60802860,"294b","ldr","r3, [pc, #0xa4]",BASE,None),
    (0x60802862,"0022","movs","r2, #0",None,None),
    (0x60802866,"9c6b","ldr","r4, [r3, #0x38]",None,None),
    (0x6080286A,"9a63","str","r2, [r3, #0x38]",None,None),
    (0x6080286C,"e4b2","uxtb","r4, r4",None,None),
    (0x608028B0,"2307","lsls","r3, r4, #0x1c",None,None),
    (0x608028B2,"0cd5","bpl","#0x608028ce",None,None),
    (0x608028B4,"164b","ldr","r3, [pc, #0x58]",CALLBACK_THUMB,None),
    (0x608028B6,"1748","ldr","r0, [pc, #0x5c]",CONTEXT_BASE,None),
    (0x608028B8,"0193","str","r3, [sp, #4]",None,None),
    (0x608028BA,"01ab","add","r3, sp, #4",None,None),
    (0x608028BC,"0290","str","r0, [sp, #8]",None,None),
    (0x608028BE,"00f59a60","add.w","r0, r0, #0x4d0",None,None),
    (0x608028C2,"93e80600","ldm.w","r3, {r1, r2}",None,None),
    (0x608028C6,"fff703fb","bl","#0x60801ed0",None,UPDATE_WRAPPER),
    (0x60801ED4,"83e80600","stm.w","r3, {r1, r2}",None,None),
    (0x60801ED8,"0146","mov","r1, r0",None,None),
    (0x60801EDA,"02a8","add","r0, sp, #8",None,None),
    (0x60801EDC,"0ccb","ldm","r3, {r2, r3}",None,None),
    (0x60801EDE,"fff7f3fe","bl","#0x60801cc8",None,0x60801CC8),
    (0x60801EE4,"fff776ff","bl","#0x60801dd4",None,UPDATE_COORDINATOR),
    (0x60801CD2,"2160","str","r1, [r4]",None,None),
    (0x60801CD4,"1221","movs","r1, #0x12",None,None),
    (0x60801CE6,"96e80300","ldm.w","r6, {r0, r1}",None,None),
    (0x60801CEA,"83e80300","stm.w","r3, {r0, r1}",None,None),
    (0x60801E54,"d5e90230","ldrd","r3, r0, [r5, #8]",None,None),
    (0x60801E58,"9847","blx","r3",None,None),
    (0x60801F0C,"104b","ldr","r3, [pc, #0x40]",BASE,None),
    (0x60801F10,"2022","moveq","r2, #0x20",None,None),
    (0x60801F12,"1022","movne","r2, #0x10",None,None),
    (0x60801F14,"9a63","str","r2, [r3, #0x38]",None,None),
)


def validate(evidence):
    """Validate selected original instructions; never claim full-file rehash."""
    validate_corpus(evidence)
    regions=evidence["functions"]
    by_address={int(i["address"],16):i for f in regions for i in f["instructions"]}
    for address,raw,op,operands,literal,target in PINS:
        i=by_address.get(address)
        if not i or (i["bytes"],i["mnemonic"],i["operands"])!=(raw,op,operands):
            raise ValueError(f"Original instruction mismatch at 0x{address:08x}")
        if literal is not None and int(i.get("literal_uint32","0"),16)!=literal:
            raise ValueError(f"Original literal mismatch at 0x{address:08x}")
        if target is not None and int(i.get("direct_target","0"),16)!=target:
            raise ValueError(f"Original call destination mismatch at 0x{address:08x}")
    return by_address


def flag_model(value):
    """Pure bit-test model. Never treats its flags as host-controlled."""
    if isinstance(value,bool) or not isinstance(value,int) or not 0<=value<=0xffffffff:
        raise ValueError("Expected unsigned 32-bit GPR6 state")
    snapshot=value&0xff  # original UXTB before LSLS #0x1c
    return {"register_value":f"0x{value:08x}",
            "low_byte_after_uxtb":f"0x{snapshot:02x}",
            "update_trigger_bit3_set":bool(snapshot & UPDATE_MASK),
            "signed_branch_condition":"enter_update_wrapper" if snapshot & UPDATE_MASK
                                      else "skip_update_wrapper",
            "register_cleared_by_signed_handler_before_update_call":True,
            "external_writer_or_usb_origin_proven":False}


def audit(evidence):
    ins=validate(evidence)
    states=[flag_model(x) for x in range(256)]
    assert sum(s["update_trigger_bit3_set"] for s in states)==128
    assert flag_model(0x10)["update_trigger_bit3_set"] is False
    assert flag_model(0x20)["update_trigger_bit3_set"] is False
    return {
       "phase":87,
       "input_source":"selected published owner-extracted original bootloader A instructions",
       "reported_original_image_sha256":evidence["sha256"],
       "raw_original_binary_rehashed_this_phase":False,
       "pinned_instruction_count":len(PINS),
       "gpr6_address":f"0x{REGISTER:08x}",
       "gpr6_handler":{
           "read_site":"0x60802866","clear_site":"0x6080286a",
           "low_byte_site":"0x6080286c",
           "bit_test_site":"0x608028b0",
           "skip_branch_site":"0x608028b2","masked_trigger":f"0x{UPDATE_MASK:02x}",
           "on_bit3_1":"update wrapper 0x60801ed0 called at 0x608028c6",
           "on_bit3_0":"branch skips that update block",
       },
       "source_of_update_wrapper_arguments":{
           "argument_r0_storage_context":f"0x{STORAGE_OBJECT:08x}",
           "argument_r1_callback_thumb":f"0x{CALLBACK_THUMB:08x}",
           "argument_r2_callback_context":f"0x{CONTEXT_BASE:08x}",
           "callback_is_fixed_signed_literal":True,
           "storage_descriptor_id":"0x12, resolved by constructor 0x60801cc8",
           "wrapper":"0x60801ed0",
           "calls_constructor":"0x60801cc8",
           "calls_coordinator":"0x60801dd4",
       },
       "other_pinned_gpr6_writer":{
           "site":"0x60801f14",
           "values":["0x10","0x20"],
           "meaning":"application-validation failure status bits; not update trigger bit3",
           "complete_writer_census":False
       },
       "pure_low_byte_cases":len(states),
       "pure_low_byte_cases_with_bit3":sum(s["update_trigger_bit3_set"] for s in states),
       "examples":{f"0x{n:02x}":flag_model(n) for n in (0x00,0x01,0x04,0x08,0x10,0x18,0x20,0x28,0x80)},
       "undetermined":{
           "who_sets_gpr6_bit3":"UNKNOWN",
           "usb_host_can_set_gpr6_bit3":"NOT_ESTABLISHED",
           "gpr6_persistence_across_reboot":"NOT_MEASURED",
           "physically_executed_update":"NOT_OBSERVED",
           "signature_bypass":"NOT_DEMONSTRATED",
           "full_bootloader_writer_census":"NOT_PERFORMED",
       },
       "decision":"GO_OFFLINE_FOR_GPR6_BIT3_WRITER_PROVENANCE; NO_GO_FOR_FLASH_EXPERIMENT",
       "device_io":False,"firmware_or_fuse_writes":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence",nargs="?",type=Path,
                   default=Path(__file__).resolve().parents[1]/"evidence/bootloader-analysis.json")
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    data=json.loads(a.evidence.read_text(encoding="utf-8"))
    output=json.dumps(audit(data),indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")


if __name__=="__main__":
    main()
