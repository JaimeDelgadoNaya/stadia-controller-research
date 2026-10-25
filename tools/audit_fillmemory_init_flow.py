"""Read-only boot/init call-path reconnaissance for the Stadia signed loader.

This tool reports *static* call sites and bounded disassembly context. It does
not pretend that function-pointer registration proves that an initializer ran.
No USB device access and no memory writes.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools import audit_fillmemory_verified as pinned

TARGET_INIT = 0x20009904
TARGET_THUMB = TARGET_INIT | 1
PROVIDER_TABLE = 0x20016074
PROVIDER_INIT_PTR_OFF = 0x16078
COMMAND_FILL_HANDLER = 0x20003380
STARTS = (
    ("memory_service_start_2e5c", 0x2E5C, 0xF0),
    ("memory_service_2eb4", 0x2EB4, 0xE0),
    ("loader_memory_init_3a98", 0x3A98, 0xA0),
    ("memory_dispatch_3b7c", 0x3B7C, 0x108),
    ("provider_initializer_9904", 0x9904, 0x88),
    ("provider_vtable_16074", 0x16074, 0x18),
)
CODE_LIMIT = 0x15800


def disasm_window(blob, offset, count):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"at":hex(i.address),"m":i.mnemonic,"ops":i.op_str}
            for i in md.disasm(blob[offset:offset+count],pinned.BASE+offset)]


def raw_pointers(blob, word):
    needle=struct.pack("<I",word)
    # Scan aligned 32-bit literal positions in the firmware; caller reachability
    # and table indirection are not inferred from a literal match.
    return [hex(pinned.BASE+i) for i in range(0, len(blob)-3,4)
            if blob[i:i+4]==needle]


def static_scan(blob):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    md.detail=True
    calls=[]
    for off in range(0x2000,CODE_LIMIT,0x1000):
        for inst in md.disasm(blob[off:min(off+0x1000,CODE_LIMIT)],pinned.BASE+off):
            if inst.mnemonic.startswith(("bl","b.")) and "0x20009904" in inst.op_str:
                calls.append({"at":hex(inst.address),"instruction":inst.mnemonic+" "+inst.op_str})
    return {
       "direct_calls_to_init_in_linear_chunk_scan":calls[:50],
       "direct_call_count":len(calls),
       "limitations":"Chunked linear decode is not an exhaustive reachable CFG. No direct calls does not exclude indirect table calls.",
    }


def audit(blob):
    if len(blob)!=pinned.SIZE or hashlib.sha256(blob).hexdigest()!=pinned.SHA256:
        raise ValueError("Require SHA-256 pinned signed original")
    u32=lambda off:struct.unpack_from("<I",blob,off)[0]
    if u32(PROVIDER_INIT_PTR_OFF)!=TARGET_THUMB:
        raise ValueError("Original provider initializer pointer changed")
    # The table pointer itself is loaded into a startup-copy RAM global.
    if u32(0x166D8)!=PROVIDER_TABLE:
        raise ValueError("Original global provider pointer changed")
    windows={name:disasm_window(blob,o,n) if o<CODE_LIMIT else
            [{"at":hex(pinned.BASE+o+4*i),"raw_word":hex(u32(o+4*i))}
             for i in range(n//4)]
            for name,o,n in STARTS}
    return {
      "original_hash_verified":True,
      "provider_init_entry":hex(TARGET_INIT),
      "provider_pointer_slot":hex(pinned.BASE+PROVIDER_INIT_PTR_OFF),
      "static_literal_pointers":{
          "init":raw_pointers(blob,TARGET_THUMB),
          "provider_table":raw_pointers(blob,PROVIDER_TABLE),
      },
      "reconnaissance":static_scan(blob),
      "bounded_windows":windows,
      "boot_before_command_init_verified":False,
      "runtime_invocation_verified":False,
      "device_access":False,
      "memory_writes":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--preview",action="store_true")
    args=p.parse_args()
    result=audit(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    if args.preview:
        print("Static references:",json.dumps(result["static_literal_pointers"]))
        print("Direct calls:",json.dumps(result["reconnaissance"]))
        for label,window in result["bounded_windows"].items():
            print("## "+label)
            for item in window:
                print(item["at"],item.get("m",""),item.get("ops",item.get("raw_word","")))
        print("Boot-order verified:",result["boot_before_command_init_verified"])
    elif not args.out:
        print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
