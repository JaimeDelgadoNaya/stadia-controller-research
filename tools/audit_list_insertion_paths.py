"""Phase 27: offline inventory of list insertions and bounded callback-pointer store patterns.

SHA-locked for owner's 128-KiB Stadia bootloader A, build 169429.
The validated calls are static firmware edges; they do not prove USB-host
reachability. A raw STR.W search only checks ONE immediate addressing mode:
other stores, dynamic aliases, and runtime pointer replacements remain possible.
No device, USB, flash or eFuse access; no proprietary image is published.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from .audit_interprocedural_aliases import decode_thumb_jump
    from .audit_pointer_initializers import scan_thumb2_positive_stores
except ImportError:
    from audit_interprocedural_aliases import decode_thumb_jump
    from audit_pointer_initializers import scan_thumb2_positive_stores

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
GLOBAL = 0x20008B78
BUCKET_BASE = 0x2000A7F8
BUCKET_STRIDE = 0x14

REGIONS = {
    "front_insert": (0x109B8, 0x109D0,
        "e7f40b71833a884652dd7fed70b9eaca3ce499508eea05250a75dfe0ac09c20b"),
    "ordered_insert": (0x109D0, 0x109FE,
        "d53845c987c5eec94c7affb3b947012eabc332fd200862692e81d318f637f4a6"),
    "ordered_tail_caller": (0x116EE, 0x11708,
        "18a02756ff0af2220e5fc3c6fede785299a858a60c065f46536913192fcad37a"),
    "indexed_insertion_site_a": (0x11A18, 0x11A34,
        "2bcd99ebeaac91067591989cf73054bfa90ff406dbc7574620b6d2ce67e4cc31"),
    "indexed_insertion_site_b": (0x11DF4, 0x11E10,
        "13563c0f939d7fcf4803ed69358b2b27f3a539b2e1fa0a5a92f79132d977211a"),
}

# Static inventory from the original Thumb disassembly. Exact branch target
# re-decoded from the private image rather than trusting the inventory.
FRONT_SITES = (
    0x114AC, 0x11808, 0x11A32, 0x11AFA, 0x11CB6,
    0x11DA2, 0x11E0C, 0x11FA4, 0x1206E
)
ORDERED_SITES = (0x11706, 0x11D68, 0x12268, 0x123A4)
ORDERED_TAIL_SITE = 0x116FA

# Selected instruction encodings for list link assignments, count increments
# and two indexed list-head computations.
ANCHORS = {
    0x109B8:"4368",  # LDR R3,[R0,#4]
    0x109BA:"9a68",  # LDR R2,[R3,#8]
    0x109BC:"4b60",  # STR R3,[R1,#4]
    0x109BE:"8a60",  # STR R2,[R1,#8]
    0x109C2:"5160",  # STR R1,[R2,#4]
    0x109C4:"9960",  # STR R1,[R3,#8]
    0x109C8:"0861",  # STR R0,[R1,#16]
    0x109CA:"0133",  # ADDS R3,#1
    0x109CC:"0360",  # STR R3,[R0]
    0x109CE:"7047",  # BX LR
    0x109D0:"0a68",  # LDR R2,[R1]
    0x109D4:"30b5",  # PUSH R4,R5,LR
    0x109D6:"0ad1",  # BNE to ordered traversal
    0x109EE:"00f10803", # ADD.W R3,R0,#8
    0x109F4:"2568",  # LDR R5,[R4]
    0x109F6:"9542",  # CMP R5,R2
    0x109F8:"efd8",  # BHI to insert after current cursor
    0x11A1C:"4ff0140c", # MOV.W R12,#20
    0x11A2E:"0cfb0030", # MLA R0,R12,R0,R3
    0x11E00:"1420",     # MOVS R0,#20
    0x11E08:"00fb0230", # MLA R0,R0,R2,R3
}

BUCKET_LITERALS = {
    0x11A7C:BUCKET_BASE,
    0x11E40:BUCKET_BASE,
}
# The direct call at both indexed sites targets front insertion.
BUCKET_CALL_SITES = (0x11A32, 0x11E0C)
INITIAL_POINTER_FIELDS = ((0x560,0xBAEC),(0x568,0xBAF2))


def fmt_addr(v):
    return f"0x{v:08x}"


def verify_direct_edges(image, front=FRONT_SITES, ordered=ORDERED_SITES, tail=ORDERED_TAIL_SITE):
    edges=[]
    for operation, sites, target in (
        ("front_insert",front,0x109B8),
        ("ordered_insert",ordered,0x109D0),
        ("ordered_insert_tail",(tail,),0x109D0)
    ):
        for site in sites:
            kind, dest=decode_thumb_jump(image,site)
            expected_kind="B.W" if operation=="ordered_insert_tail" else "BL"
            if (kind,dest)!=(expected_kind,BASE+target):
                raise ValueError(f"Branch edge mismatch at {fmt_addr(BASE+site)}")
            edges.append({"site":fmt_addr(BASE+site),"target":fmt_addr(dest),
                          "branch_kind":kind,"operation":operation,
                          "host_reachable":"NOT ESTABLISHED"})
    return edges


def audit(image, expected_sha256=SHA256, fingerprints=REGIONS):
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte Stadia bootloader A")
    digest=hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Bootloader SHA-256 mismatch")
    for name,(start,end,known) in fingerprints.items():
        if not 0<=start<end<=SIZE or hashlib.sha256(image[start:end]).hexdigest()!=known:
            raise ValueError(f"Code region fingerprint mismatch: {name}")
    for offset,encoding in ANCHORS.items():
        b=bytes.fromhex(encoding)
        if image[offset:offset+len(b)]!=b:
            raise ValueError(f"Instruction anchor mismatch at {fmt_addr(BASE+offset)}")
    for offset,expected in BUCKET_LITERALS.items():
        if struct.unpack_from("<I",image,offset)[0]!=expected:
            raise ValueError(f"Indexed bucket literal mismatch at {fmt_addr(BASE+offset)}")
    edges=verify_direct_edges(image)
    field_store_candidates={}
    for off,expected_site in INITIAL_POINTER_FIELDS:
        matches=scan_thumb2_positive_stores(image,off)
        expected=(fmt_addr(BASE+expected_site),"r4","r3")
        if [(x["at"],x["base_register"],x["source_register"]) for x in matches]!=[expected]:
            raise ValueError(f"Pointer field immediate-STR.W census changed at {off:#x}")
        field_store_candidates[hex(off)]=matches

    return {
        "phase":27,"build":169429,"sha256_verified":True,
        "image_sha256":digest,"image_bytes":len(image),
        "hardware_access":False,"usb_transactions":False,
        "flash_or_fuse_operations":False,
        "attested_regions":[{"name":name,"start":fmt_addr(BASE+start),
                              "end_exclusive":fmt_addr(BASE+end),
                              "sha256":digest} for name,(start,end,digest) in fingerprints.items()],
        "list_insertion":{
            "front_insertion_function":"0x608109b8",
            "ordered_insertion_function":"0x608109d0",
            "front_direct_bl_sites":len(FRONT_SITES),
            "ordered_direct_bl_sites":len(ORDERED_SITES),
            "ordered_direct_tail_branches":1,
            "verified_static_edges":edges,
            "front_semantics":{
                "head_argument":"r0; runtime address depends on caller",
                "node_argument":"r1; runtime address depends on caller",
                "writes":["node+4=existing next","node+8=existing previous",
                          "existing next+4=node","existing previous+8=node",
                          "node+16=head","head+0=count+1"],
            },
            "ordered_semantics":{
                "head_argument":"r0; runtime address depends on caller",
                "node_argument":"r1; key loaded from [r1]",
                "operation":"linked insertion with conditional key-based traversal",
                "writes":"linked-list pointer updates and head count increment",
                "sort_order":"comparison and placement depend on the current list data; not externally validated",
            },
            "disassembly_scope":"selected direct BL/B.W edges, not an exhaustive whole-program CFG",
        },
        "indexed_bucket_examples":[
            {"callsite":"0x60811a32",
             "bucket_literal":"0x60811a7c",
             "formula":"r0=0x2000a7f8+20*index (index loaded from controller field)",
             "node_provenance":"r1 passed from another register; actual node runtime address unknown"},
            {"callsite":"0x60811e0c",
             "bucket_literal":"0x60811e40",
             "formula":"r0=0x2000a7f8+20*index (index loaded from context+0x2c)",
             "node_provenance":"r1 derived from dynamic node pointer+4"},
        ],
        "comparison_with_phase26_heads":{
            "phase26_initial_heads":["0x20009114","0x20009128"],
            "indexed_bucket_base":"0x2000a7f8",
            "different_ram_region_at_known_base":True,
            "bounds_and_runtime_bucket_index":"NOT VERIFIED",
            "cannot_equate_all_callers_to_phase26_heads":True,
        },
        "known_pointer_field_write_search":{
            "fields":["global+0x560","global+0x568"],
            "raw_positive_immediate_STRW_candidates":field_store_candidates,
            "result":"only original constructor STR.W encodings in selected scan",
            "scope":"positive-immediate Thumb2 STR.W only, no alias/multiple-store/dynamic address proof",
            "later_reassignment":"NOT PROVEN OR EXCLUDED",
        },
        "conclusions":{
            "list_operations":"insert routines and static callsites verified",
            "callback_field_overlap":"NOT DEMONSTRATED",
            "host_to_list_insertion":"NOT DEMONSTRATED",
            "host_usb_to_flash_writer":"NOT DEMONSTRATED",
            "hab_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Local owner-extracted 128-KiB bootloader A")
    p.add_argument("--out",type=Path,help="Optional local-only JSON output")
    a=p.parse_args()
    output=json.dumps(audit(a.bootloader.read_bytes()),indent=2)+"\n"
    if a.out:
        a.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")


if __name__=="__main__":
    main()
