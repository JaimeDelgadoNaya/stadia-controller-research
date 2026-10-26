"""Phase47: identify dedicated signed OEM EP0-IN / EP0-OUT callback installer.

Hash-verified original signed Bruce update, not physical device firmware. Pins
the two registrar invocations (first endpoint literal, then endpoint-address
byte forced to zero) and rollback of 0x80 on second registration failure.
Records the original callback literal and input R1 context without pretending
that ROM instructions imply a live configured USB object or host reachability.
No USB, flash, or eFuse access.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches
from tools.audit_bruce_ep0_slot_handoff_phase46 import endpoint_index

BASE=ASSUMED_XIP_BASE
INSTALLER=0x60054F30
FIRST_REG=0x60054F4A
SECOND_REG=0x60054F5C
ROLLBACK=0x60054F68
REGISTRAR=0x600D10B8
DEREGISTRAR=0x600D10F6
FN_LITERAL_ADDR=0x60054F74
EP_LITERAL_ADDR=0x60054F78

PIN={
    0x60054F30:("push","{r4, r5, lr}"),
    0x60054F32:("ldr","r3, [pc, #0x40]"),
    0x60054F34:("sub","sp, #0x1c"),
    0x60054F36:("mov","r5, r0"),
    0x60054F38:("add","r2, sp, #0xc"),
    0x60054F3A:("strd","r3, r1, [sp, #0xc]"),
    0x60054F3E:("ldr","r3, [pc, #0x38]"),
    0x60054F40:("add","r1, sp, #4"),
    0x60054F42:("str","r3, [sp, #4]"),
    0x60054F44:("movs","r3, #1"),
    0x60054F46:("strb.w","r3, [sp, #8]"),
    0x60054F4A:("bl","#0x600d10b8"),
    0x60054F4E:("mov","r4, r0"),
    0x60054F50:("cbnz","r0, #0x60054f6c"),
    0x60054F52:("strb.w","r0, [sp, #6]"),
    0x60054F56:("add","r2, sp, #0xc"),
    0x60054F58:("add","r1, sp, #4"),
    0x60054F5A:("mov","r0, r5"),
    0x60054F5C:("bl","#0x600d10b8"),
    0x60054F60:("mov","r4, r0"),
    0x60054F62:("cbz","r0, #0x60054f6c"),
    0x60054F64:("movs","r1, #0x80"),
    0x60054F66:("mov","r0, r5"),
    0x60054F68:("bl","#0x600d10f6"),
    0x60054F6C:("mov","r0, r4"),
}


CALLER_PINS={
    0x600D0BCA:("mov","r5, r1"),
    0x600D0BCE:("mov","r4, r0"),
    0x600D0BD2:("bl","#0x60054f7c"),
    0x600D0BD6:("cbnz","r0, #0x600d0bfc"),
    0x600D0BD8:("cmp","r5, #1"),
    0x600D0BDA:("bne","#0x600d0bee"),
    0x600D0BDC:("ldr","r1, [sp, #4]"),
    0x600D0BDE:("mov","r0, r4"),
    0x600D0BE0:("bl","#0x60054f30"),
}
EP0_HANDLER_PINS={
    0x60054D74:("ldr","r3, [r1, #4]"),
    0x60054D82:("mov","r5, r0"),
    0x60054D84:("mov","r6, r1"),
    0x60054D86:("mov","r7, r2"),
    0x60054D9A:("ldr","r4, [r2, #8]"),
    0x60054DA2:("bl","#0x600d1178"),
    0x60054DB2:("ldr","r2, [r6]"),
    0x60054DB8:("ldrh","r3, [r2, #2]"),
    0x60054DBC:("ldrh","r3, [r2, #4]"),
    0x60054DC0:("ldrh","r3, [r2, #6]"),
    0x60054DC4:("ldrb","r1, [r2, #1]"),
    0x60054DC8:("ldrb","r2, [r2]"),
    0x60054DCA:("tst.w","r2, #0x60"),
    0x60054DD0:("bne","#0x60054dfc"),
    0x60054DD4:("ldr.w","r6, [r3, r1, lsl #2]"),
    0x60054DE4:("blx","r6"),
    0x60054DF6:("bl","#0x600d0b60"),
    0x60054E50:("bl","#0x600d0bc8"),
    0x60054E8E:("bl","#0x600d0bc8"),
}
def validate_pins(actual):
    for pc,exp in PIN.items():
        if actual.get(pc)!=exp:
            raise ValueError("Original OEM EP0 pair installer drift "+hex(pc)+" "+repr(actual.get(pc)))
    return len(PIN)


def literal_at(pc,disp):
    return ((pc+4)&~3)+disp


def pin_pair(image):
    rows=decode(image,INSTALLER,0x60054F70)
    validate_pins({x["pc"]:(x["m"],x["op"]) for x in rows})
    if literal_at(0x60054F32,0x40)!=FN_LITERAL_ADDR:
        raise ValueError("callback PC-relative literal address moved")
    if literal_at(0x60054F3E,0x38)!=EP_LITERAL_ADDR:
        raise ValueError("endpoint PC-relative literal address moved")
    callback=struct.unpack_from("<I",image,FN_LITERAL_ADDR-BASE)[0]
    endpoint_word=struct.unpack_from("<I",image,EP_LITERAL_ADDR-BASE)[0]
    addr=(endpoint_word >> 16)&0xFF
    handler={q["pc"]:(q["m"],q["op"])
             for q in decode(image,0x60054D74,0x60054E98)}
    for pc,expected in EP0_HANDLER_PINS.items():
        if handler.get(pc)!=expected:
            raise ValueError("Original EP0 handler SETUP dispatch drift "+hex(pc))
    callers={q["pc"]:(q["m"],q["op"])
             for q in decode(image,0x600D0BC8,0x600D0BE8)}
    for pc,expected in CALLER_PINS.items():
        if callers.get(pc)!=expected:
            raise ValueError("Signed EP0 installer caller gate drift "+hex(pc))
    return {
        "installer":hex(INSTALLER),
        "pinned_original_instructions":len(PIN)+len(CALLER_PINS)+len(EP0_HANDLER_PINS),
        "ep0_original_signed_handler_entry":"0x60054d74",
        "ep0_signed_handler_dataflow":{
            "SETUP_like_data_pointer":"[R6] where R6 is callback input R1 (0x60054d84)",
            "bRequest_byte":"0x60054dc4 LDRB R1,[R2,#1]",
            "bmRequestType_byte":"0x60054dc8 LDRB R2,[R2]",
            "request_type_bits":"0x60054dca TST.W R2,#0x60",
            "standard_request_local_table":"0x60054dd4 LDR.W R6,[R3,R1,LSL#2] -> 0x60054de4 BLX R6",
            "nonstandard_branches_to":"0x60054dfc; signed branches contain BL 0x600d0bc8",
            "class_control_bridge_call_sites":["0x60054e50","0x60054e8e"],
            "class10_selected_or_host_reachable":"UNVERIFIED",
        },
        "caller_has_signed_configuration_guard":"0x600d0bd2 BL 0x60054f7c; if success and R5(input R1)==1, call installer",
        "first_original_callback_literal_at":hex(FN_LITERAL_ADDR),
        "signed_callback_pointer":hex(callback),
        "original_endpoint_record_literal_at":hex(EP_LITERAL_ADDR),
        "endpoint_record_word":hex(endpoint_word),
        "first_record_endpoint_byte_at_plus_2":hex(addr),
        "first_slot_index":endpoint_index(addr),
        "second_record_endpoint_forced_zero_at":"0x60054f52 STRB R0,[SP,#6] after first registrar returned zero",
        "second_slot_index":0,
        "original_callback_reused_for_both":True,
        "original_context_input":"function R1, saved as word [SP+0x10] at 0x60054f3a; reused for both",
        "first_registration":"0x60054f4a -> 0x600d10b8",
        "second_registration":"0x60054f5c -> 0x600d10b8",
        "rollback_if_second_failed":"0x60054f64 R1=0x80; 0x60054f68 -> 0x600d10f6",
        "precondition":"USB object base in original function R0 and context in R1",
        "real_runtime_called":"NOT VERIFIED",
        "host_writable_callback_pointer":"NOT DEMONSTRATED",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed original Bruce SHA-256 required")
    pair=pin_pair(image)
    calls=find_inbound_branches(image,only_target=INSTALLER)
    handler_window=decode(image,0x60054D74,0x60054EA0)
    setup_window=decode(image,0x600D0BC8,0x600D0C14)
    return {"phase":47,"signed_oem_original_sha_verified":True,
            "source":"original signed update, not installed-flash readback",
            "ep0_pair":pair,
            "original_ep0_handler_candidate_window":[hex(q["pc"])+" "+q["m"]+" "+q["op"] for q in handler_window],
            "original_caller_setup_window":[hex(q["pc"])+" "+q["m"]+" "+q["op"] for q in setup_window],
            "immediate_branch_callers_to_ep0_installer":calls["direct_branch_candidates"][:30],
            "live_EP0_slot_contents":"UNMEASURED",
            "live_usb_class_object":"UNVERIFIED",
            "host_entry_class10_reachable":"UNVERIFIED",
            "unsigned_execution":"NOT DEMONSTRATED",
            "device_used":False,"flash_written":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    o=p.parse_args()
    result=audit(o.image.read_bytes())
    if o.out:o.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE47 OEM EP0 DEDICATED PAIR",json.dumps(result["ep0_pair"]))
    print("PHASE47 EP0 PAIR INSTALLER INBOUND",json.dumps(result["immediate_branch_callers_to_ep0_installer"]))
    print("PHASE47 EP0 CALLBACK CODE",json.dumps(result["original_ep0_handler_candidate_window"]))
    print("PHASE47 EP0 CALLER CONTROL FLOW",json.dumps(result["original_caller_setup_window"]))
    print("PHASE47 NO PHYSICAL USB/FLASH; LIVE EP0: UNVERIFIED")
if __name__=="__main__":
    main()
