"""Phase 23: offline, anchored interprocedural alias hand-offs (Stadia bootloader A).

This is deliberately NOT whole-firmware symbolic execution. It verifies
selected direct Thumb call/branch edges and explicit register arithmetic
on normal code paths. It stops at unknown callees and does not infer
host USB reachability, callback replacement, flash writes, or HAB bypass.

Requires owner's private 131072-byte image, SHA-256 locked by default.
No USB/device access, firmware execution, writes, or eFuse operations.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
GLOBAL = 0x20008B78

# Each wrapper executes a Thumb16 LDR PC-literal into r0 followed by BL.
# All literal sites and callee instruction encodings were examined offline.
WRAPPERS = (
    ("normal_constructor", 0xC0B2, 0xC0B4, 0xC0BC, 0xBAC0),
    ("controller_service_a", 0x2502, 0x2504, 0x2528, 0xB218),
    ("controller_service_b", 0x8136, 0x8138, 0x8140, 0xB218),
    ("subsystem_initialization", 0xFB4A, 0xFB4C, 0xFB60, 0xB17C),
)
# Callee entry and the straight-line group of derived subobject arguments.
# Thumb encodings are anchored so labels alone never prove a relation.
ANCHORS = {
    0xBAC4: "0446",        # MOV R4,R0, constructor
    0xB17C: "10b5",        # PUSH {r4,lr}
    0xB17E: "0446",        # MOV R4,R0
    0xB182: "00f5ad60",    # ADD.W R0,R0,#0x568
    0xB18A: "04f5ac60",    # ADD.W R0,R4,#0x560
    0xB192: "04f5c660",    # ADD.W R0,R4,#0x630
    0xB19A: "04f5af60",    # ADD.W R0,R4,#0x578
    0xB218: "00f5c660",    # ADD.W R0,R0,#0x630
    0xB21C: "fef74ebc",    # B.W 0x60809ABC
    0x9ABC: "10b5",        # PUSH {r4,lr}
    0x9ABE: "0446",        # MOV R4,R0
    0x9AC0: "1430",        # ADDS R0,#0x14
}
SUBOBJECT_CALLS = (
    (0xB186, 0xA990, 0x568, "device_misc_subobject"),
    (0xB18E, 0x22A0, 0x560, "device_state_subobject"),
    (0xB196, 0x990C, 0x630, "controller_data_subobject"),
    (0xB19E, 0x9D98, 0x578, "cdc_labelled_subobject"),
)
TAIL_TARGET = (0xB21C, 0x9ABC)
NEXT_CALL = (0x9AC2, 0x9688)

def fmt(value):
    return f"0x{value:08x}"


def decode_thumb_jump(image, off):
    """Thumb-2 BL immediate and unconditional B.W T4 only."""
    if off < 0 or off+4 > len(image) or off & 1:
        raise ValueError("Invalid Thumb jump offset")
    h1,h2=struct.unpack_from("<HH",image,off)
    if h1&0xF800 != 0xF000:
        raise ValueError("Not a Thumb jump")
    if (h2&0xD000)==0xD000:
        kind="BL"
    elif (h2&0xD000)==0x9000:
        kind="B.W"
    else:
        raise ValueError("Unsupported Thumb branch encoding")
    s,j1,j2=(h1>>10)&1,(h2>>13)&1,(h2>>11)&1
    i1,i2=1^(j1^s),1^(j2^s)
    imm=(s<<24)|(i1<<23)|(i2<<22)|((h1&1023)<<12)|((h2&2047)<<1)
    target=(BASE+off+4+(imm-(1<<25) if s else imm))&0xFFFFFFFF
    return kind,target


def decode_literal_r0(image, off):
    """Decode a Thumb16 LDR R0,[PC,#imm] and fetch its literal address."""
    hw=struct.unpack_from("<H",image,off)[0]
    if hw&0xFF00 != 0x4800:
        raise ValueError("Expected Thumb16 PC-relative load into R0")
    target=((BASE+off+4)&~3)+4*(hw&255)
    if target-BASE < 0 or target-BASE+4 > len(image):
        raise ValueError("Literal outside verified image")
    return target, struct.unpack_from("<I",image,target-BASE)[0]


def audit(image, expected_sha256=SHA256):
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte Stadia bootloader A")
    sha=hashlib.sha256(image).hexdigest()
    if sha!=expected_sha256:
        raise ValueError("SHA-256 mismatch for bootloader A")
    for off,encoded in ANCHORS.items():
        raw=bytes.fromhex(encoded)
        if image[off:off+len(raw)] != raw:
            raise ValueError(f"Machine-code anchor changed at {fmt(BASE+off)}")

    entrances=[]
    for name,load,call,literal,callee in WRAPPERS:
        got_literal, value=decode_literal_r0(image,load)
        if (got_literal,value)!=(BASE+literal,GLOBAL):
            raise ValueError(f"Unexpected global pointer input: {name}")
        kind,target=decode_thumb_jump(image,call)
        if (kind,target)!=("BL",BASE+callee):
            raise ValueError(f"Changed direct call edge: {name}")
        entrances.append({
            "name":name,"global_load":fmt(BASE+load),
            "source_literal":fmt(got_literal),"callsite":fmt(BASE+call),
            "target":fmt(target),"argument_r0":fmt(GLOBAL),
            "entry_edge_verified":True,"executed_by_host":"NOT ESTABLISHED"
        })

    subobjects=[]
    for call,target,offset,description in SUBOBJECT_CALLS:
        kind,dst=decode_thumb_jump(image,call)
        if (kind,dst)!=("BL",BASE+target):
            raise ValueError(f"Changed subobject BL edge at {fmt(BASE+call)}")
        subobjects.append({
            "callsite":fmt(BASE+call),"target":fmt(dst),
            "argument_r0":fmt(GLOBAL+offset),
            "global_offset":hex(offset),"role_hint":description,
            "callee_body_checked":False,
            "condition":"sequential path; earlier calls must return normally"
        })
    kind,target=decode_thumb_jump(image,TAIL_TARGET[0])
    if (kind,target)!=("B.W",BASE+TAIL_TARGET[1]):
        raise ValueError("Changed service tail branch")
    kind2,target2=decode_thumb_jump(image,NEXT_CALL[0])
    if (kind2,target2)!=("BL",BASE+NEXT_CALL[1]):
        raise ValueError("Changed first tail-callee call")

    return {
        "phase":23,"bootloader_build":169429,
        "sha256_verified":True,"sha256":sha,"image_bytes":len(image),
        "hardware_access":False,"usb_transactions":False,
        "flash_or_fuse_writes":False,
        "bounded_direct_global_handoffs":entrances,
        "subsystem_initializer":{
            "callee":"0x6080b17c","preserves_global_as":"r4 at 0x6080b17e",
            "derived_argument_calls":subobjects,
            "scope":"Only anchored straight-line argument setup; callees not audited"
        },
        "controller_service":{
            "entry":"0x6080b218",
            "derived_argument_r0":fmt(GLOBAL+0x630),
            "tail_branch_site":fmt(BASE+TAIL_TARGET[0]),
            "tail_branch_target":fmt(target),
            "tail_target":"0x60809abc",
            "next_derived_argument_r0":fmt(GLOBAL+0x644),
            "first_tail_callee":fmt(target2),
            "scope":"Assumes normal entry and stops at first unmodelled callee"
        },
        "constructor":{
            "callee":"0x6080bac0",
            "alias_copy":"0x6080bac4 MOV r4,r0",
            "known_initial_field_stores":[
                "0x6080bb50","0x6080bb5a","0x6080bb6c","0x6080bb70"],
            "later_setter":"NOT DEMONSTRATED"
        },
        "argument_aliases":{
            "subobject_offsets_inspected":["0x560","0x568","0x578","0x630","0x644"],
            "bulk_out_callback_global_offset":"0x600",
            "bulk_in_callback_global_offset":"0x5f8",
            "warning":"Different offsets alone do not rule out writes via aliases inside callees"
        },
        "callers_or_callees_host_reachable":"NOT DEMONSTRATED",
        "interprocedural_callback_replacement":"NOT PROVEN OR EXCLUDED",
        "host_bulk_out_to_parser":"NOT DEMONSTRATED",
        "host_to_flash_writer":"NOT DEMONSTRATED",
        "hab_closed_bypass":"NOT DEMONSTRATED",
        "custom_firmware_execution":"NOT DEMONSTRATED"
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(result,encoding="utf-8")
    else:
        print(result,end="")

if __name__=="__main__":
    main()
