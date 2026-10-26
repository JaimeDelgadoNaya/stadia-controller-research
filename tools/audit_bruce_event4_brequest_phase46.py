"""Phase46: signed endpoint event-type 4 -> class forwarder bRequest translation.

Disambiguates two meanings of R1: endpoint wrappers set R1 to internal
event 1/2/3/4; the class forwarder's event-4 TBB branch sets R1 to byte
1 of a SETUP-shaped buffer. Signed update bytes and branch-table positions
are verified, but runtime EP0 registration and SETUP source remain unproven.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_slot_handoff_phase46 import audit as audit_slots

BASE=ASSUMED_XIP_BASE
EVENT_TBB_PC=0x600D0E68
EVENT_TABLE_BASE=EVENT_TBB_PC+4
EVENT_COUNT=4
EVENT4_EXPECTED=0x600D0EA2
PINS={
    0x600CFC1A:("mov","r0, r2"),
    0x600CFC26:("mov","r2, r1"),
    0x600CFC28:("movs","r1, #4"),
    0x600CFC2A:("bx","r3"),
    0x600D0E62:("subs","r1, #1"),
    0x600D0E64:("cmp","r1, #3"),
    0x600D0E66:("bhi","#0x600d0e76"),
    0x600D0E68:("tbb","[pc, r1]"),
    0x600D0EA2:("ldr","r1, [r2]"),
    0x600D0EA4:("ldrb","r3, [r1]"),
    0x600D0EB8:("ldrb","r1, [r1, #1]"),
    0x600D0EBE:("bx","r3"),
}


def decode_original_events(image):
    ins={}
    for a,b in ((0x600CFC1A,0x600CFC2C),(0x600D0E58,0x600D0E6C),
                (0x600D0EA2,0x600D0EC0)):
        ins.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,a,b)})
    for pc,expect in PINS.items():
        if ins.get(pc)!=expect:
            raise ValueError("Original signed event4-to-bRequest anchor drift "+hex(pc))
    vals=image[EVENT_TABLE_BASE-BASE:EVENT_TABLE_BASE-BASE+EVENT_COUNT]
    if len(vals)!=EVENT_COUNT:
        raise ValueError("Original event table truncated")
    dest=[EVENT_TABLE_BASE+2*x for x in vals]
    if dest[3]!=EVENT4_EXPECTED:
        raise ValueError("Event4 signed table target differs: raw="+repr(list(vals))+" dest="+repr([hex(v) for v in dest]))
    return {"table_bytes":[hex(x) for x in vals],
            "destination_by_event_id":[{"internal_event":n+1,"target":hex(pc)}
                                       for n,pc in enumerate(dest)],
            "event4_targets_class_setup_decode":True,
            "pins_verified":len(PINS)}


def symbolic_chain_event4(*, endpoint_registered, class_vtable_matches,
                          setup_pointer_valid, bm_request_type=0x21,
                          iface_matches=True):
    """Static branch-gate check only; does not call original OEM functions."""
    if not endpoint_registered:
        return "EP0_SLOT_UNKNOWN"
    if not class_vtable_matches:
        return "CLASS_EVENT_METHOD_UNKNOWN"
    if not setup_pointer_valid:
        return "SETUP_BUFFER_POINTER_UNVERIFIED"
    if not (0<=bm_request_type<=255):
        raise ValueError("invalid bmRequestType")
    if bm_request_type & 0x1f != 1:
        return "INTERFACE_RECIPIENT_REJECTED"
    if not iface_matches:
        return "INTERFACE_NUMBER_REJECTED"
    return "CONDITIONAL_CLASS10_BREQUEST_BYTE_PATH"


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact signed Bruce OEM SHA-256 required")
    slot=audit_slots(image)
    table=decode_original_events(image)
    if slot["signed_event_adapters"]["type4"]["r1_internal_event_tag"]!=4:
        raise ValueError("original endpoint event4 adapter drift")
    return {
        "phase":46,"signed_original_sha_verified":True,
        "signed_event4_table":table,
        "r1_internal_event_transition":{
            "endpoint_slot_callback":"0x600cfc1b (signed adapter pointer, only if installed)",
            "adapter_entry":"0x600cfc1a",
            "adapter_R0":"original endpoint callback context R2",
            "adapter_R2":"original endpoint callback event structure R1",
            "adapter_R1":"constant internal event tag 4",
            "class_forwarder":"0x600d0e58 (only if object vtable points there)",
            "forwarder_R1":"internal event 4 -> 3 after SUBS",
            "event_TBB":"0x600d0e68 branches to 0x600d0ea2 for event type 4",
            "forwarder_load_SETUP":"0x600d0ea2 LDR R1,[R2]",
            "forwarder_LOAD_bRequest":"0x600d0eb8 LDRB R1,[R1,#1]",
            "class10_dispatch":"CONDITIONAL as proven in phase45",
        },
        "endpoint0_adapter_currently_registered":"UNVERIFIED",
        "vtable_runtime_target_class10":"UNVERIFIED",
        "setup_bytes_from_physical_USB1":"UNVERIFIED",
        "no_direct_host_callback_pointer_control":"NOT DEMONSTRATED",
        "hardware_used":False,"flash_modified":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    o=p.parse_args()
    report=audit(o.image.read_bytes())
    if o.out:o.out.write_text(json.dumps(report,indent=2)+"\n")
    print("PHASE46 VERIFIED CLASS EVENT4 TABLE",json.dumps(report["signed_event4_table"]))
    print("PHASE46 EVENT4 TO BREQUEST BRIDGE",json.dumps(report["r1_internal_event_transition"]))
    print("PHASE46 EP0 LIVE SLOT, VTOR AND HOST ROUTE: UNVERIFIED")

if __name__=="__main__":
    main()
