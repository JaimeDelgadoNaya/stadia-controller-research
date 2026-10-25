"""Phase 29: offline index-writer provenance in selected Stadia bootloader functions.

Owner's original bootloader A, build 169429, exactly 128 KiB / SHA-256
locked. This is a *bounded static inventory*, not a whole-program CFG,
proof that every object index is within range, or validation of index
controllability from USB. No USB traffic, flash/eFuse writes or device IO.
No proprietary firmware belongs in GitHub or CI.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
INDEX_FIELD = 0x2C
ORIGINAL_BUCKET_BASE = 0x2000A7F8
BUCKET_STRIDE = 20

REGIONS = {
    "object_constructor_clamp": (0x1154C,0x115A8,
        "1619774c84a3e4f91da570a7658639d6c09d322dd327bb537c2c08b6603aa06e"),
    "index_restore_from_global": (0x11F48,0x11FD0,
        "3e28843d0516a8f1a1440fd8c73ed062c90170edec825c2ace4d3177e6eedfa4"),
    "index_restore_from_member": (0x11FEC,0x12078,
        "ba102732fed712ef9aa14d9f15d22d97c2b1d8b30fc02b9658809b0f0b711e67"),
    "index_update_from_argument": (0x1208C,0x12126,
        "6fb623947593ec80d3a0b6953c81ddddb16026d2ce65eb9df87fbcbdd7162614"),
}
# Bytes independently checked against the real image. A site must be
# authenticated by whole-image hash, local-region fingerprint and anchor.
ANCHORS = {
    0x11590:"089e",  # LDR R6,[SP,#0x20] (caller-supplied index)
    0x11596:"0f2e",  # CMP R6,#15
    0x1159C:"28bf",  # IT HS (unsigned >=)
    0x1159E:"0f26",  # MOVHS R6,#15
    0x115A0:"e662",  # STR R6,[R4,#0x2C]
    0x115A2:"c4e91465", # STRD R6,R5,[R4,#0x50] (same initialized limit, other state)
    0x11F52:"c36a",  # LDR R3,[R0,#0x2C]
    0x11F58:"c96a",  # LDR R1,[R1,#0x2C]
    0x11F5A:"8b42",  # CMP R3,R1 before branching
    0x11F5C:"38d2",  # BHS 0x11FD0 (candidate guard for THIS route)
    0x11F8A:"3a68",  # LDR R2,[R7] -> pointer to another object
    0x11F8E:"d26a",  # LDR R2,[R2,#0x2C]
    0x11F90:"e262",  # STR R2,[R4,#0x2C]
    0x11FAC:"3b68",  # LDR R3,[R7]
    0x11FB0:"db6a",  # LDR R3,[R3,#0x2C]
    0x11FB2:"e362",  # STR R3,[R4,#0x2C]
    0x12050:"236d",  # LDR R3,[R4,#0x50]
    0x12056:"e362",  # STR R3,[R4,#0x2C]
    0x1208E:"0d46",  # MOV R5,R1: initial incoming argument value
    0x120A6:"236d",  # LDR R3,[R4,#0x50]
    0x120A8:"9d42",  # CMP R5,R3
    0x120AA:"38bf",  # IT LO (unsigned less)
    0x120AC:"1d46",  # MOVLO R5,R3
    0x120D6:"e562",  # STR R5,[R4,#0x2C] (chosen max on local path)
}
WRITES = (
    {"site":0x115A0,"source":"R6 from stack argument [SP,#0x20], unsigned-clamped to <=15",
     "precondition":"CMP R6,#15; IT HS; MOVHS R6,#15",
     "local_range":"0..15 for normal local constructor path",
     "phase":"constructor"},
    {"site":0x11F90,"source":"R2=[ [0x2000A7EC] + 0x2C ] (another runtime object)",
     "precondition":"Earlier CMP/BHS compares current object index with other object's +0x2C",
     "local_range":"not independently established; loaded field value",
     "phase":"runtime"},
    {"site":0x11FB2,"source":"R3=[ [0x2000A7EC] + 0x2C ] (another runtime object)",
     "precondition":"alternative branch after list-head comparison",
     "local_range":"not independently established; loaded field value",
     "phase":"runtime"},
    {"site":0x12056,"source":"R3=[R4+0x50] (object's stored reference index)",
     "precondition":"branch in state-change method; no independent numeric cap here",
     "local_range":"depends on later history of object's +0x50",
     "phase":"runtime"},
    {"site":0x120D6,"source":"R5=max_unsigned(incoming R1,[R4+0x50]) on local path",
     "precondition":"CMP R5,R3; IT LO; MOVLO R5,R3",
     "local_range":"not proven <=15: incoming value and current +0x50 unbounded by this block",
     "phase":"runtime"},
)
LITERALS = {
    0x11FE0:0x2000A7EC,
    0x12084:ORIGINAL_BUCKET_BASE,
    0x12130:0x2000A7EC,
    0x12134:ORIGINAL_BUCKET_BASE,
}
EXPECTED_RAW_STR_SITES = (0x115A0,0x11F90,0x11FB2,0x12056,0x120D6)

def fmt(address):
    return f"0x{address:08x}"

def scan_thumb16_word_stores(image, displacement=INDEX_FIELD,
                             start=0x11400,end=0x12200):
    """Thumb16 positive-immediate STR word encoding scan; raw, NOT CFG."""
    if not isinstance(displacement,int) or displacement%4 or not 0<=displacement<=124:
        raise ValueError("Thumb16 STR displacement must be 0..124, 4-byte aligned")
    if not 0<=start<end<=len(image) or (start|end)&1:
        raise ValueError("Scan range must be halfword aligned and inside image")
    matches=[]
    for off in range(start,end-1,2):
        half=struct.unpack_from("<H",image,off)[0]
        if half&0xF800==0x6000 and ((half>>6)&31)*4==displacement:
            matches.append({
                "address":fmt(BASE+off),
                "base_register":f"r{(half>>3)&7}",
                "value_register":f"r{half&7}",
                "encoding":image[off:off+2].hex(),
                "reachable":"NOT ESTABLISHED BY RAW SCAN",
            })
    return matches

def clamp_initial_index_unsigned(argument):
    """Pure mathematical model of the 0x11596/9C/9E Thumb predicate."""
    if not isinstance(argument,int) or not 0<=argument<1<<32:
        raise ValueError("Expected unsigned 32-bit input")
    return min(argument,15)

def pick_unsigned_max(argument, reference):
    """Pure model of CMP+IT LO+MOVLO, not a global safety predicate."""
    if not all(isinstance(v,int) and 0<=v<1<<32 for v in (argument,reference)):
        raise ValueError("Expected two unsigned 32-bit inputs")
    return max(argument,reference)

def audit(image, expected_sha256=SHA256, fingerprints=REGIONS):
    if len(image)!=SIZE:
        raise ValueError("Expected exact 131072-byte bootloader A")
    actual=hashlib.sha256(image).hexdigest()
    if actual!=expected_sha256:
        raise ValueError("Bootloader SHA-256 mismatch")
    for name,(start,end,digest) in fingerprints.items():
        if not 0<=start<end<=SIZE or hashlib.sha256(image[start:end]).hexdigest()!=digest:
            raise ValueError(f"Region fingerprint mismatch: {name}")
    for site,encoding in ANCHORS.items():
        raw=bytes.fromhex(encoding)
        if image[site:site+len(raw)]!=raw:
            raise ValueError(f"Instruction anchor mismatch: {fmt(BASE+site)}")
    for site,value in LITERALS.items():
        if struct.unpack_from("<I",image,site)[0]!=value:
            raise ValueError(f"Literal mismatch: {fmt(BASE+site)}")
    candidates=scan_thumb16_word_stores(image)
    found=[int(c["address"],16)-BASE for c in candidates]
    if found!=list(EXPECTED_RAW_STR_SITES):
        raise ValueError(f"Local Thumb16 STR #0x2C candidate census changed: {found!r}")
    return {
        "phase":29,"build":169429,"size_bytes":SIZE,
        "sha256_verified":True,"sha256":actual,
        "device_access":False,"usb_transactions":False,
        "flash_or_fuse_operations":False,
        "regions":[{"name":name,"start":fmt(BASE+start),
                    "end_exclusive":fmt(BASE+end),"sha256":digest}
                   for name,(start,end,digest) in fingerprints.items()],
        "index_field_offset":hex(INDEX_FIELD),
        "selected_function_range":["0x60811400","0x60812200"],
        "selected_word_store_candidates":candidates,
        "source_evidence":[{"address":fmt(BASE+entry["site"]),
                            **{k:v for k,v in entry.items() if k!="site"}}
                           for entry in WRITES],
        "initializer":{
            "index_write":"0x608115a0",
            "same_initial_value_stored_to_plus_0x50":"0x608115a2 STRD R6,R5,[R4,#0x50]",
            "conditional_unsigned_range":[0,15],
            "independent_proof_of_later_bounds":False,
        },
        "runtime_field_sources":{
            "index_copies_from_another_object":["0x60811f90","0x60811fb2"],
            "index_restored_from_same_object_plus_0x50":"0x60812056",
            "index_written_after_unsigned_max_selection":"0x608120d6",
            "later_field_mutation_and_aliases":"NOT EXHAUSTIVELY RESOLVED",
        },
        "limits":{
            "local_constructor_cap_not_global_invariant":True,
            "size_of_indexed_bucket_array":"UNKNOWN",
            "runtime_index_domain":"UNKNOWN",
            "indirect_field_sources":"NOT FULLY RESOLVED",
            "out_of_bounds_index":"NOT DEMONSTRATED",
            "USB_host_control":"NOT DEMONSTRATED",
            "host_to_flash_writer":"NOT DEMONSTRATED",
            "HAB_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
        "scope":"Four SHA-locked code blocks plus Thumb16 STR-imm #0x2C candidate census; not a complete whole-program CFG or alias proof.",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Private matching bootloader A image")
    p.add_argument("--out",type=Path,help="Local-only JSON report")
    args=p.parse_args()
    out=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(out,encoding="utf-8")
    else:
        print(out,end="")

if __name__=="__main__":
    main()
