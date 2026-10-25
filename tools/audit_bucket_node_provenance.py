"""Phase 28: offline, SHA-locked provenance for two indexed list insertions.

Reconstructs selected Thumb instruction chains in the owner's Stadia
bootloader A, build 169429, 131072 bytes. It does NOT prove that an
index is externally controllable, that validation is absent elsewhere,
or that any physical memory boundary is violated. No device contact,
USB transfers, flash/fuse operations or private binary publication.

The findings are specific to chosen instruction windows, not a whole
program CFG, executable emulator, or proof of runtime reachability.
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
BUCKET_BASE = 0x2000A7F8
STRIDE = 0x14
INSERT_TARGET = 0x109B8

REGIONS = {
    "route_a_node_and_index": (
        0x119EC, 0x11A46,
        "2d91db7b02d7c7b80a725572b5e24dc242dae2cf5ba68f01d265d8d57e991d44"),
    "route_b_node_and_index": (
        0x11DC8, 0x11E2E,
        "1d6cc5cbce079b652003101b81bff555d8f2165032d5c06d8d8d0d0fdb16ec30"),
    "earlier_bucket_read": (
        0x119A0, 0x119C4,
        "5a8345ddf7936e83fb67fe5e51e9de588cab48e194845aca49ee0a4b256a7634"),
    "front_insertion_callee": (
        0x109B8, 0x109D0,
        "e7f40b71833a884652dd7fed70b9eaca3ce499508eea05250a75dfe0ac09c20b"),
}

# Important local Thumb encodings; derived from actual build 169429 bytes.
ANCHORS = {
    0x119EC: "f8da2000",  # LDR.W R2,[R10]
    0x119F0: "d268",      # LDR R2,[R2,#0xC]
    0x119F2: "d668",      # LDR R6,[R2,#0xC]
    0x119FE: "06f10408",  # ADD.W R8,R6,#4: node address
    0x11A14: "f06a",      # LDR R0,[R6,#0x2C]: bucket index
    0x11A1C: "4ff0140c",  # MOV.W R12,#20
    0x11A26: "154b",      # LDR R3,[PC,#0x54]: bucket base
    0x11A2C: "4146",      # MOV R1,R8: node argument
    0x11A2E: "0cfb0030",  # MLA R0,R12,R0,R3: head base + stride*index
    0x11A36: "3868",      # LDR R0,[R7] AFTER insertion
    0x11A38: "f16a",      # LDR R1,[R6,#0x2C] AFTER insertion
    0x11A3A: "c26a",      # LDR R2,[R0,#0x2C]
    0x11A3C: "9142",      # CMP R1,R2 AFTER insertion
    0x11DCA: "c368",      # LDR R3,[R0,#0xC]
    0x11DCC: "dc68",      # LDR R4,[R3,#0xC]
    0x11DEC: "251d",      # ADDS R5,R4,#4: node address
    0x11DF6: "e26a",      # LDR R2,[R4,#0x2C]: bucket index
    0x11E00: "1420",      # MOVS R0,#20
    0x11E04: "2946",      # MOV R1,R5: node argument
    0x11E06: "0e4b",      # LDR R3,[PC,#0x38]: bucket base
    0x11E08: "00fb0230",  # MLA R0,R0,R2,R3: head base + stride*index
    0x11E12: "e26a",      # LDR R2,[R4,#0x2C] AFTER insertion
    0x11E14: "1b68",      # LDR R3,[R3]
    0x11E16: "db6a",      # LDR R3,[R3,#0x2C]
    0x11E18: "9a42",      # CMP R2,R3 AFTER insertion
}
LITERALS = {0x11A7C: BUCKET_BASE, 0x11E40: BUCKET_BASE}
DIRECT_BL = {
    0x11A04: 0x109FE,  # route A unlinks old node before indexed reinsertion
    0x11A32: INSERT_TARGET,
    0x11DF0: 0x109FE,  # route B conditionally unlinks other linked node
    0x11E0C: INSERT_TARGET,
}
SITES = {
    "A": {
        "callsite":0x11A32,
        "node_setup_at":0x119FE,
        "index_load_at":0x11A14,
        "head_calc_at":0x11A2E,
        "node_source":"R6+4, where R6 is loaded from [[R10]+0xC]+0xC",
        "index_source":"word [R6+0x2C]",
        "index_register":"R0",
        "head_argument":"R0 = 0x2000A7F8 + 20 * R0 (32-bit MLA)",
        "node_argument":"R1 = R8 = R6+4",
        "post_call_comparison":"0x60811A3C CMP R1,R2 compares freshly loaded node index against field of object loaded via R7",
        "pre_call_index_guard_in_inspected_window":"NOT IDENTIFIED",
        "other_possible_guards":"UNKNOWN",
    },
    "B": {
        "callsite":0x11E0C,
        "node_setup_at":0x11DEC,
        "index_load_at":0x11DF6,
        "head_calc_at":0x11E08,
        "node_source":"R4+4, where R4 = [[incoming R0+0xC]+0xC]",
        "index_source":"word [R4+0x2C]",
        "index_register":"R2",
        "head_argument":"R0 = 0x2000A7F8 + 20 * R2 (32-bit MLA)",
        "node_argument":"R1 = R5 = R4+4",
        "post_call_comparison":"0x60811E18 CMP R2,R3 compares freshly loaded node index against field reached via another global pointer",
        "pre_call_index_guard_in_inspected_window":"NOT IDENTIFIED",
        "other_possible_guards":"UNKNOWN",
    },
}


def address(value):
    return f"0x{value:08x}"


def hypothetical_head(index):
    """Pure 32-bit modeled MLA arithmetic, NOT an assessed safe address.

    This is deliberately not a validity checker; valid bucket indices
    and allocated RAM-array extent are unknown.
    """
    if not isinstance(index,int) or not 0 <= index < (1<<32):
        raise ValueError("Index must be a 32-bit unsigned integer")
    return (BUCKET_BASE + STRIDE*index) & 0xFFFFFFFF


def audit(image, expected_sha256=SHA256, fingerprints=REGIONS):
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte bootloader A")
    whole=hashlib.sha256(image).hexdigest()
    if whole != expected_sha256:
        raise ValueError("Unexpected bootloader SHA-256")
    for name,(start,end,digest) in fingerprints.items():
        if not 0 <= start < end <= SIZE:
            raise ValueError(f"Invalid range for {name}")
        if hashlib.sha256(image[start:end]).hexdigest() != digest:
            raise ValueError(f"Range SHA-256 mismatch for {name}")
    for offset,raw in ANCHORS.items():
        encoding=bytes.fromhex(raw)
        if image[offset:offset+len(encoding)] != encoding:
            raise ValueError(f"Instruction anchor mismatch at {address(BASE+offset)}")
    for offset,value in LITERALS.items():
        if struct.unpack_from("<I",image,offset)[0] != value:
            raise ValueError(f"Bucket literal mismatch at {address(BASE+offset)}")
    for site,target in DIRECT_BL.items():
        kind,resolved=decode_thumb_jump(image,site)
        if (kind,resolved)!=("BL",BASE+target):
            raise ValueError(f"Direct BL target mismatch at {address(BASE+site)}")
    details=[]
    for key,s in SITES.items():
        if not (s["index_load_at"] < s["head_calc_at"] < s["callsite"]):
            raise ValueError("Unexpected order in bucket index calculation")
        details.append({
            "route":key, "callsite":address(BASE+s["callsite"]),
            "callee":address(BASE+INSERT_TARGET),
            "node_setup":address(BASE+s["node_setup_at"]),
            "node_source":s["node_source"],
            "node_argument":s["node_argument"],
            "index_load":address(BASE+s["index_load_at"]),
            "index_source":s["index_source"],
            "index_register":s["index_register"],
            "head_calculation":address(BASE+s["head_calc_at"]),
            "head_argument":s["head_argument"],
            "comparison_after_call":s["post_call_comparison"],
            "guard_before_call_in_selected_window":s["pre_call_index_guard_in_inspected_window"],
            "other_guards_or_state_invariants":s["other_possible_guards"],
            "live_object_and_index_values":"UNKNOWN",
            "externally_host_controlled":"NOT DEMONSTRATED",
        })
    return {
        "phase":28,"build":169429,"image_bytes":len(image),
        "sha256_verified":True,"sha256":whole,
        "hardware_access":False,"usb_io":False,"flash_or_fuse_writes":False,
        "attested_regions":[
            {"name":name,"start":address(BASE+start),"end_exclusive":address(BASE+end),
             "sha256":digest} for name,(start,end,digest) in fingerprints.items()],
        "bucket_base":address(BUCKET_BASE),"bucket_stride_bytes":STRIDE,
        "insertion_sites":details,
        "facts":{
            "node_argument_is_subobject_address":True,
            "index_from_word_at_node_object_plus_0x2c":True,
            "comparison_seen_after_insertion_at_both_sites":True,
            "pre_insertion_bounds_check_in_selected_local_windows":"NOT IDENTIFIED",
            "bucket_array_element_count":"UNKNOWN",
            "actual_index_bounds":"UNKNOWN",
            "caller_earlier_validation":"NOT EXHAUSTIVELY TRACED",
            "dynamic_runtime_node_addresses":"NOT MEASURED",
        },
        "critical_limits":{
            "out_of_bounds_memory_access":"NOT DEMONSTRATED",
            "USB_input_controls_index":"NOT DEMONSTRATED",
            "callback_field_modified":"NOT DEMONSTRATED",
            "host_to_flash_write":"NOT DEMONSTRATED",
            "hab_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
        "methodology":"Whole image SHA-256, four subrange hashes, exact instruction bytes, literal words and decoded direct BL targets. No full CFG or dynamic emulation.",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Private owner-extracted bootloader A")
    p.add_argument("--out",type=Path,help="Local-only JSON output")
    args=p.parse_args()
    result=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(result,encoding="utf-8")
    else:
        print(result,end="")


if __name__=="__main__":
    main()
