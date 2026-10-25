"""Phase 26: SHA-locked offline provenance of two initialized pointers and list heads.

Reads the owner's local Stadia bootloader A (build 169429). This is STATIC
normal-constructor inference, NOT measured live RAM, proven USB reachability
or a whole-program alias analysis. No USB commands, flash writes or fuse
operations. Never commit the proprietary bootloader to GitHub.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from .audit_interprocedural_aliases import decode_thumb_jump
except ImportError:
    from audit_interprocedural_aliases import decode_thumb_jump

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
GLOBAL = 0x20008B78
POINTER_TARGET_OFFSET = 0x134
FIELD_POINTERS = (0x560, 0x568)
FIELD_ZERO_BYTE = 0x570
LIST_HEAD_OFFSETS = (0x59C, 0x5B0)
CALLBACK_OFFSETS = (0x5F8, 0x5FC, 0x600, 0x604)

REGIONS = {
    "global_pointer_constructor": (0xBAE2, 0xBB10,
        "b03bf98db18da2054fd7d80b2a4cbe9cf7d6f8d51bb5351db34541e73d021883"),
    "list_head_initializer": (0x1099C, 0x109B2,
        "8f64714e4d62060e0a8b9a64105cb9285c0780b3b11e15fd63c86079332c58cc"),
    "list_head_callers": (0x10B70, 0x10BAA,
        "33bf649bb7a60d945eb4ff950b62a24014b8f8f6815f4d06b4d765af162b7f62"),
    "nested_constructor": (0x10C04, 0x10C1E,
        "0be7fbb5d9ee7e919c2c9cacc617048a28060f34edc2d46a76ecb16b8d7666f3"),
    "transfer_caller": (0xA9A0, 0xAA30,
        "61486e672e5d0a614618d43027316d8b0d9ac3a70331f4d2c0b606c0e16fdb06"),
}
ANCHORS = {
    0xBACE:"0025",        # MOVS R5,#0 before pointer initializer
    0xBAE2:"04f59a73",    # ADD.W R3,R4,#0x134
    0xBAE8:"84f87055",    # STRB.W R5,[R4,#0x570] (one byte, not pointer)
    0xBAEC:"c4f86035",    # STR.W R3,[R4,#0x560]
    0xBAF2:"c4f86835",    # STR.W R3,[R4,#0x568]
    0xBAF8:"84f86425",    # STRB.W R2,[R4,#0x564]
    0xBB00:"84f86c35",    # STRB.W R3,[R4,#0x56c]
    0xBB0C:"c4f87435",    # STR.W R3,[R4,#0x574]
    0x1099C:"00f10803",   # ADD.W R3,R0,#0x8
    0x109A0:"4ff0ff32",   # MOV.W R2,#0xffffffff
    0x109A4:"4360",       # STR R3,[R0,#4]
    0x109A6:"0361",       # STR R3,[R0,#0x10]
    0x109A8:"c0e90223",   # STRD R2,R3,[R0,#8]
    0x109AC:"0023",       # MOVS R3,#0
    0x109AE:"0360",       # STR R3,[R0]
    0x10B70:"95b9",       # CBNZ R5 to 0x10b98
    0x10B98:"04f11000",   # ADD.W R0,R4,#0x10
    0x10B9C:"fff7fefe",   # BL list initializer
    0x10BA0:"04f12400",   # ADD.W R0,R4,#0x24
    0x10BA4:"fff7fafe",   # BL list initializer
    0x10C06:"0121",       # MOVS R1,#1 before calling nested constructor
    0x10C1A:"fff78dff",   # BL 0x60810b38
    0xA9B8:"0068",       # LDR R0,[R0] from first wrapper's object field
    0xA9E6:"2868",       # LDR R0,[R5] from same object field
    0xAA24:"2868",       # LDR R0,[R5] from same object field
    0xA9DC:"0724",       # MOVS R4,#7; previous phase notes were mistaken
}
DIRECT_CALLS = {
    0x10B9C:0x1099C,
    0x10BA4:0x1099C,
    0x10C1A:0x10B38,
}
STRW_OFFSETS = (0x560,0x568)


def address(number):
    return f"0x{number:08x}"


def scan_thumb2_positive_stores(image, displacement, start=0x1000, end=0x14F00):
    """RAW candidate encodings for STR.W Rt,[Rn,#imm12]; not a CFG."""
    if not isinstance(displacement,int) or not 0<=displacement<=0xFFF:
        raise ValueError("12-bit displacement required")
    if start<0 or end>len(image) or start>=end or (start|end)&1:
        raise ValueError("Invalid aligned scan range")
    matches=[]
    for offset in range(start,end-3,2):
        h1,h2=struct.unpack_from("<HH",image,offset)
        if h1 & 0xFFF0 == 0xF8C0 and h2 & 0xFFF == displacement:
            matches.append({"at":address(BASE+offset),"base_register":f"r{h1&15}",
                            "source_register":f"r{h2>>12}","encoding":image[offset:offset+4].hex()})
    return matches


def initialized_list_head(base):
    """Model exact STR/STRD effects of 0x6081099c on a passed-in head."""
    if not isinstance(base,int) or base<0 or base>0xFFFFFFEF or base%4:
        raise ValueError("Aligned RAM list-head address required")
    link=base+8
    return {
        "base":address(base),
        "count_field": {"at":address(base),"value":address(0)},
        "next_field": {"at":address(base+4),"value":address(link)},
        "marker_field": {"at":address(base+8),"value":address(0xFFFFFFFF),
                         "type":"sentinel marker, NOT a pointer"},
        "link_field": {"at":address(base+12),"value":address(link)},
        "owner_or_link_field": {"at":address(base+16),"value":address(link)},
        "initial_state_only":True,
    }


def audit(image, expected_sha256=SHA256, fingerprints=REGIONS):
    """Only synthetic tests may override the default whole-image digest."""
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte Stadia bootloader A")
    digest=hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Bootloader SHA-256 mismatch")
    for name,(start,end,expected) in fingerprints.items():
        if not 0<=start<end<=SIZE or hashlib.sha256(image[start:end]).hexdigest()!=expected:
            raise ValueError(f"Machine code region mismatch: {name}")
    for site,hexbytes in ANCHORS.items():
        data=bytes.fromhex(hexbytes)
        if image[site:site+len(data)]!=data:
            raise ValueError(f"Instruction anchor mismatch at {address(BASE+site)}")
    for site,target in DIRECT_CALLS.items():
        kind,decoded=decode_thumb_jump(image,site)
        if (kind,decoded)!=("BL",BASE+target):
            raise ValueError(f"Constructor call edge mismatch at {address(BASE+site)}")
    census={}
    for field,expected_at in ((0x560,0xBAEC),(0x568,0xBAF2)):
        matches=scan_thumb2_positive_stores(image,field)
        if [(x["at"],x["base_register"],x["source_register"]) for x in matches] != [
            (address(BASE+expected_at),"r4","r3")]:
            raise ValueError(f"Pointer initializer STR.W candidate census changed: {field:#x}")
        census[hex(field)]=matches

    pointer=GLOBAL+POINTER_TARGET_OFFSET
    fields=[
        {"offset_from_global":hex(field),"ram_field_address":address(GLOBAL+field),
         "initial_value":address(pointer),"constructor_store":address(BASE+site),
         "word_width_bytes":4}
        for field,site in ((0x560,0xBAEC),(0x568,0xBAF2))
    ]
    heads=[initialized_list_head(GLOBAL+off) for off in LIST_HEAD_OFFSETS]
    return {
        "phase":26,"bootloader_build":169429,"sha256_verified":True,
        "image_sha256":digest,"bytes":SIZE,
        "hardware_access":False,"usb_transactions":False,
        "flash_or_fuse_writes":False,
        "normal_constructor_pointer_initialization":{
            "constructor":"0x6080bac0",
            "r4":"global object base 0x20008b78, conditional constructor entry",
            "computed_pointer_instruction":"0x6080bae2 ADD.W r3,r4,#0x134",
            "computed_pointer_value":address(pointer),
            "pointer_fields":fields,
            "field_global_plus_0x570":{"ram_address":address(GLOBAL+FIELD_ZERO_BYTE),
                "byte_initial_value":0,
                "constructor_store":"0x6080bae8 STRB.W r5,[r4,#0x570]",
                "correction":"THIS IS A BYTE FIELD, NOT A THIRD INITIALIZED POINTER"},
            "initial_parameter_addresses_for_0x60809048":{
                "input+0x6c":address(pointer+0x6C),
                "input+0xa4":address(pointer+0xA4),
                "input+0xf8":address(pointer+0xF8),
                "input+0x154":address(pointer+0x154),
                "input+0x158":address(pointer+0x158),
                "input+0x15c":address(pointer+0x15C),
            },
            "all_initial_parameter_addresses_below_callback_fields":True,
            "limitations":"Only constructor-initialized values; runtime mutation and callee effects not excluded.",
        },
        "thumb2_strw_census":{
            "range":[address(BASE+0x1000),address(BASE+0x14F00)],
            "raw_positive_immediate_matches":census,
            "limitation":"Two selected offsets and opcode class, not exhaustive writes or pointer alias analysis",
        },
        "linked_list_head_initialization":{
            "nested_constructor_call":"0x60810c1a -> 0x60810b38",
            "condition":"R1=1 in inspected constructor path; 0x60810b70 branches on nonzero R5",
            "two_direct_calls":["0x60810b9c -> 0x6081099c",
                                "0x60810ba4 -> 0x6081099c"],
            "head_arguments":[address(GLOBAL+off) for off in LIST_HEAD_OFFSETS],
            "heads":heads,
            "note":"Sentinels/self-pointers at initialization are NOT live node addresses after list mutations",
        },
        "prior_phase_25_erratum":{
            "statement":"global+0x570 as a third independent pointer source",
            "corrected":"global+0x570 is initialized using STRB to zero; no pointer interpretation proven",
            "phase_24_25_reports_with_provisional_field_aliases":"require this correction"
        },
        "claims":{
            "later_field_mutation":"NOT PROVEN OR EXCLUDED",
            "callback_alias_from_dynamic_list_nodes":"NOT PROVEN OR EXCLUDED",
            "host_usb_to_flash_writer":"NOT DEMONSTRATED",
            "hab_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Private local matching bootloader-a.bin")
    p.add_argument("--out",type=Path,help="Optional private local JSON path")
    args=p.parse_args()
    value=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(value,encoding="utf-8")
    else:
        print(value,end="")


if __name__=="__main__":
    main()
