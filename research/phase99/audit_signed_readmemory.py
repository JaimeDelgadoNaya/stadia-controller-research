"""Read-only, SHA-pinned static investigation of the signed OEM ReadMemory command.

Downloads are performed by GitHub Actions, not by this script. Never makes
USB, SDP, flash, register, SWD or OTP requests. A code excerpt is NOT proof
that the original controller permits reading its internal ROM.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path

SHA = "c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5"
SIZE = 100672
BASE = 0x20000000
TABLE = 0x15978
WINDOWS = {
    "ReadMemory handler": (0x35a4, 512),
    "ReadMemory surrounding code": (0x37a4, 256),
    "memory backend": (0x3b7c, 384),
    "range policy": (0x39a8, 192),
}

def entry(data: bytes, tag: int) -> dict:
    handler, data_handler, flag = struct.unpack_from("<3I", data, TABLE + (tag-1)*12)
    return {"tag": tag, "handler": hex(handler), "data_handler": hex(data_handler),
            "enabled": bool(flag & 255)}

def audit(data: bytes, decoder=None) -> dict:
    if len(data) != SIZE: raise ValueError("Unexpected signed loader size")
    sha = hashlib.sha256(data).hexdigest()
    if sha != SHA: raise ValueError("Unexpected signed loader SHA")
    commands = {str(t): entry(data,t) for t in (3,4,9,10)}
    if commands["3"]["handler"] != "0x200035a5" or not commands["3"]["enabled"]:
        raise ValueError("ReadMemory entry differs from verified prior evidence")
    if commands["9"]["enabled"] or commands["10"]["enabled"]:
        raise ValueError("Unexpected Execute/Call state")
    result = {
        "source_sha256": sha, "commands": commands, "windows": {},
        "actual_internal_stadia_rom_read": False,
        "readmemory_internal_rom_policy_proven": False,
        "hardware_connected": False, "usb_traffic": False,
        "exploitation_attempted": False,
    }
    for name,(pos,size) in WINDOWS.items():
        buf = data[pos:pos+size]
        if len(buf) != size: raise ValueError("Truncated bounded excerpt")
        w = {"address":hex(BASE+pos),"sha256":hashlib.sha256(buf).hexdigest()}
        if decoder is not None:
            ins=list(decoder.disasm(buf,BASE+pos))
            w["instructions"]=[f"{i.address:#010x}: {i.mnemonic} {i.op_str}" for i in ins[:100]]
            w["direct_calls"]=[f"{i.address:#010x} -> {i.op_str}"
                                for i in ins if i.mnemonic in ("bl","blx")]
        result["windows"][name] = w
    return result

if __name__ == "__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("pinned_original",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    data=audit(a.pinned_original.read_bytes(),Cs(CS_ARCH_ARM,CS_MODE_THUMB))
    text=json.dumps(data,indent=2)+"\n"
    if a.out:a.out.write_text(text,encoding="utf-8")
    print(json.dumps({"SHA_verified":True,"command_table":data["commands"],
          "direct_calls_by_window":{k:v.get("direct_calls",[]) for k,v in data["windows"].items()},
          "read_rom_policy_proven":False,"device_touched":False},indent=2))
