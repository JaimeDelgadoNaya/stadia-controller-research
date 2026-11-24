"""Bounded offline read of exact OEM-signed loader policy pointer provenance.

This script inspects only known ROM addresses in the pinned 100672-byte
published original. No device, USB, RAM command, ROM execution or flashing.
A synthetic reconstruction of initialized global RAM is NOT a device snapshot.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from research.phase99.audit_signed_readmemory import SHA, SIZE, BASE

INIT_RUNTIME_BASE = 0x20208000
INIT_IMAGE_OFFSET = 0x164d8
INIT_LENGTH = 0x830
POLICY_HELPER_PTR_LITERAL = BASE + 0x3a38  # Thumb LDR at 0x200039f8, PC+0x3c

def word(data: bytes, addr: int):
    if BASE <= addr <= BASE + len(data) - 4:
        off = addr - BASE
        space = "signed_image"
    elif INIT_RUNTIME_BASE <= addr <= INIT_RUNTIME_BASE + INIT_LENGTH - 4:
        off = INIT_IMAGE_OFFSET + (addr - INIT_RUNTIME_BASE)
        space = "initialized_RAM_copy_model"
    else:
        raise ValueError(f"Virtual address not safely mapped in original signed image: {addr:#010x}")
    return struct.unpack_from("<I", data, off)[0], space

def trace(data: bytes):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("Signed OEM loader identity mismatch")
    first,space = word(data, POLICY_HELPER_PTR_LITERAL)
    # At 0x200039f8, the code loads this literal into r3 and then derefs
    # [r3,#4]. Do not guess later pointer fields from a numerical value alone.
    out={"original_sha256":SHA,"literal_at_0x20003a38":hex(first),
        "literal_provenance":space,"next_dereference_at":hex(first+4),
        "next_dereference_status":"NOT_VERIFIED","target":None,
        "readmemory_rom_0x00200000_allowed":None,
        "real_device_read_tested":False,"writes_to_hardware":False}
    try:
        second,space2=word(data,first+4)
        out["next_dereference_status"]="RESOLVED_IN_STATIC_OR_INIT_COPY"
        out["next_dereference_target"]=hex(second)
        out["next_dereference_source"]=space2
        # This is an address candidate, not proof of an enabled range.
        try:
            vals=[word(data,second+4*i)[0] for i in range(16)]
            out["candidate_table_words"]=[hex(v) for v in vals]
        except ValueError as e:
            out["candidate_table_note"]=str(e)
    except ValueError as e:
        out["next_dereference_note"]=str(e)
    return out

if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("file",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    result=trace(a.file.read_bytes())
    text=json.dumps(result,indent=2)+"\n"
    if a.out:a.out.write_text(text)
    print(text)
