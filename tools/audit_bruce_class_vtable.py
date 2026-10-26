"""Resolve OEM Bruce USB class vtable initialization and supplied class callback.

Strict original signed Bruce SHA256. Static analysis only, no device access,
USB transfer, writes or custom code execution.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode,callers_of_known

BASE=ASSUMED_XIP_BASE
LITERAL_LOADS={
 0x600553BA:("#0x40",0x600553FC),
 0x600553BE:("#0x38",0x600553F8),
 0x600553D0:("#0x24",0x600553F8),
}
ANCHORS={
 0x60055320:("push","{r4, r5, r6, lr}"),
 0x60055324:("mov","r6, r1"),
 0x60055326:("mov","r5, r2"),
 0x6005532E:("bl","#0x60055024"),
 0x6005533A:("str","r6, [r4, #4]"),
 0x60055340:("str","r4, [r5]"),
 0x600553B4:("subs","r3, r5, #2"),
 0x600553BA:("ldr","r3, [pc, #0x40]"),
 0x600553BE:("ldr","r2, [pc, #0x38]"),
 0x600553C0:("str","r3, [r4, #4]"),
 0x600553C2:("str","r4, [r7]"),
 0x600553C6:("ldr","r3, [r4, #4]"),
 0x600553C8:("ldr","r3, [r3]"),
 0x600553CA:("blx","r3"),
 0x600D0EB6:("ldr","r3, [r0, #4]"),
 0x600D0EB8:("ldrb","r1, [r1, #1]"),
 0x600D0EBA:("ldr","r3, [r3]"),
 0x600D0EBE:("bx","r3"),
}

def check_anchors(seen):
    for pc,expected in ANCHORS.items():
        if seen.get(pc)!=expected:
            raise ValueError("Bruce class vtable semantic drift at "+hex(pc))
    return True

def literal_at(image,pc):
    if not(BASE<=pc<=BASE+0xFF000-4) or pc%4:
        raise ValueError("literal not aligned in signed XIP region")
    return struct.unpack_from("<I",image,pc-BASE)[0]

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact original signed Bruce hash/size required")
    rows={}
    for lo,hi in [(0x60055320,0x6005534C),
                  (0x600553B4,0x600553D4),
                  (0x600D0EB6,0x600D0EC0)]:
        rows.update({i["pc"]:(i["m"],i["op"]) for i in decode(image,lo,hi)})
    check_anchors(rows)
    literals={}
    for pc,(_,at) in LITERAL_LOADS.items():
        literals[hex(pc)]={
            "source":hex(at),
            "word":hex(literal_at(image,at)),
            "source_as_code":False}
    refs=callers_of_known(image,{
        "init_global_class_callback":0x60055320,
        "configure_class_device_context":0x60055350,
        "get_or_allocate_global_class":0x60055024,
        "control_setup_router":0x600D0E58,
    },max_examples=8)
    return {
        "original_sha256_verified":True,"sha256":IMAGE_SHA256,
        "semantic_pins_verified":len(ANCHORS),
        "literal_loads":literals,
        "upstream_direct_BL_xrefs":{
            k:[row["callsite"] for row in v] for k,v in refs.items()},
        "init_class_function":{
            "pc":"0x60055320","loads_callback_argument":"0x60055324 MOV R6,R1",
            "writes_callback_to_global_object":"0x6005533a STR R6,[R4,#4]",
            "global_object_initializer":"0x60055024",
            "live_callback_pointer":"NOT VERIFIED",
            "host_bRequest_is_callback_pointer":"NOT DEMONSTRATED"},
        "configure_class_object":{
            "pc":"0x60055350",
            "loads_class_vtable_literal":"0x600553ba",
            "writes_class_vtable_pointer_to_object":"0x600553c0",
            "calls_first_vtable_method":"0x600553c6..0x600553ca",
            "vtable_identified_from_literal":"SEE LITERAL_LOADS; NO HOST REACHABILITY"},
        "class_setup_event":{
            "pc":"0x600d0e58",
            "forwards_bRequest_to_stored_function":"0x600d0eb8; 0x600d0eba; 0x600d0ebe",
            "physical_reachability":"NOT VERIFIED"},
        "device_io":False,"flash_written":False,"custom_execution":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("SIGNED CLASS VTABLE SEMANTIC PINS",result["semantic_pins_verified"])
    print("CLASS INITIALIZER LITERALS",json.dumps(result["literal_loads"]))
    print("CLASS CONFIGURE DIRECT BL CALLS",json.dumps(result["upstream_direct_BL_xrefs"]))
    print("GLOBAL CLASS CALLBACK STORE",result["init_class_function"]["writes_callback_to_global_object"])
    print("HOST bRequest RECEIVER CODE: NOT YET CONNECTED TO CLASS-SPECIFIC FUNCTION")
    print("DEVICE IO/FIRMWARE WRITES: NONE")

if __name__=="__main__":
    main()
