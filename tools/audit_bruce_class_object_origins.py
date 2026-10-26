"""Inspect OEM Bruce control-class object origins without hardware access.

The original signed update must match the known SHA-256; the parser never
opens USB, modifies firmware, guesses loaded RAM, or assumes that literal
vtable proximity implies a runtime registration.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

BASE=ASSUMED_XIP_BASE
SIGNED_END=BASE+0xFF000
WINDOWS={
    "table_words":(0x60104B38,0x60104BE8),
    "control_dispatch_full":(0x600D0DF0,0x600D0F06),
    "class_constructor_and_initializer":(0x600552D0,0x60055410),
    "class_global_utility":(0x60054FC0,0x600550C0),
    "callsite_control_setup":(0x600D0B08,0x600D0DE0),
    "class_device_adaptor":(0x600CFC00,0x600CFEB0),
}
# Neighboring words are checked as raw data, not Thumb instructions.
KNOWN={
    0x60104BA4:0x60055321,
    0x60104BA8:0x600D0ECB,
    0x60104BAC:0x600D0E59,
    0x60104BC4:0x6005556D,
}
TARGETS={0x60104B80,0x60104B84,0x60104B88,0x60104B8C,
         0x60104B90,0x60104B94,0x60104B98,0x60104B9C,
         0x60104BA0,0x60104BA4,0x60104BA8,0x60104BAC,
         0x60104BB0,0x60104BB4,0x60104BB8,0x60104BBC,
         0x60104BC0,0x60104BC4,0x60104BC8,0x60104BCC}

def _word(blob,address):
    if address%4 or address<BASE or address+4>SIGNED_END:
        raise ValueError("raw literal outside authenticated XIP content")
    return struct.unpack_from("<I",blob,address-BASE)[0]

def annotate_words(blob, start, stop):
    if start%4 or stop%4 or not(BASE<=start<stop<=SIGNED_END):
        raise ValueError("invalid word range")
    return [{"address":hex(pc),"word":hex(_word(blob,pc)),
             "is_xip_thumb_pointer": bool(_word(blob,pc)&1 and
                  BASE<=(_word(blob,pc)&~1)<SIGNED_END)}
            for pc in range(start,stop,4)]

def _thumb(blob,start,stop):
    if not(BASE<=start<stop<=SIGNED_END):
        raise ValueError("invalid code window")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str}
            for i in md.disasm(blob[start-BASE:stop-BASE],start)]

def pointer_literal_census(blob, targets=TARGETS):
    # Scan the *whole signed application including ITCM relocation source*
    # for exact little-endian words, aligned and unaligned.
    out=[]
    for address in sorted(targets):
        needle=struct.pack("<I",address)
        offsets=[]
        offset=0
        while True:
            offset=blob.find(needle,offset,0xFF030)
            if offset<0: break
            offsets.append(offset)
            offset+=1
        out.append({"target":hex(address),"count":len(offsets),
                    "source_file_offsets":[hex(x) for x in offsets[:25]],
                    "aligned_sources":[hex(x) for x in offsets[:25] if x%4==0]})
    return out

def candidate_class_records(blob, start=0x60104B80, count=4):
    """Interpret four 16-byte-shaped blocks; do not claim runtime registration."""
    rows=[]
    for n in range(count):
        pc=start+n*16
        ident=_word(blob,pc)
        methods=[_word(blob,pc+o) for o in (4,8,12)]
        rows.append({
            "source_xip_address":hex(pc),
            "selector_word":hex(ident),
            "method_thumb_pointers":[hex(x) for x in methods],
            "all_three_methods_signed_thumb":all(
                x&1 and BASE<=(x&~1)<SIGNED_END for x in methods),
            "zero_methods":all(x==0 for x in methods),
            "record_size_hypothesis_bytes":16,
            "runtime_class_selection":"NOT VERIFIED",
        })
    if [x["selector_word"] for x in rows]!=["0x1","0x2","0x4","0xa"]:
        raise ValueError("Unexpected class table selector layout")
    if not all(x["all_three_methods_signed_thumb"] for x in rows[:3]):
        raise ValueError("Signed class method candidates changed")
    if not rows[3]["zero_methods"]:
        raise ValueError("Expected zero method trailer not present")
    return rows

def wider_pc_literal_origin_scan(blob, lo=0x601049E0, hi=0x60104C40):
    """Raw PC-relative XIP LDR candidate references in a broader range.

    This is a sequential, non-reachability-validating Thumb scan.
    """
    import re
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
    pattern=re.compile(r'^\w+, \[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]$',re.I)
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    initial=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    candidates=[]
    for off in range(initial,0xFF000,0x4000):
        for ins in md.disasm(blob[off:min(off+0x4000,0xFF000)],BASE+off):
            if not ins.mnemonic.startswith("ldr"):
                continue
            m=pattern.fullmatch(ins.op_str)
            if not m:
                continue
            adr=((ins.address+4)&~3)+(int(m.group(1),0) if m.group(1) else 0)
            if not BASE<=adr<SIGNED_END or adr%4:
                continue
            value=_word(blob,adr)
            if lo<=value<hi:
                candidates.append({
                    "pc":hex(ins.address),
                    "load":ins.mnemonic+" "+ins.op_str,
                    "literal_addr":hex(adr),
                    "literal_word":hex(value),
                    "proves_class_object_instantiation":False,
                })
    return candidates


def inspect(blob):
    if len(blob)!=IMAGE_SIZE or hashlib.sha256(blob).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact original OEM signed Bruce image")
    for address,value in KNOWN.items():
        if _word(blob,address)!=value:
            raise ValueError("known pointer drift at "+hex(address))
    return {
      "sha256_verified":True,"sha256":IMAGE_SHA256,
      "raw_neighborhood":annotate_words(blob,*WINDOWS["table_words"]),
      "record_layout_hypotheses":candidate_class_records(blob),
      "wider_pc_literal_refs":wider_pc_literal_origin_scan(blob),
      "exact_table_pointer_refs":pointer_literal_census(blob),
      "code_windows":{name:_thumb(blob,a,b)
                      for name,(a,b) in WINDOWS.items() if name!="table_words"},
      "interpretation_limits":[
        "Original signed update, not installed flash",
        "Sequential disassembly may include literal pools and non-executable data",
        "A signed function pointer is not evidence of runtime class registration",
        "No live EP0 object, host class request behavior or user code execution proved"
      ],
      "usb_used":False,"device_written":False
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bruce",type=Path)
    ap.add_argument("--out",type=Path)
    ap.add_argument("--preview",action="store_true")
    a=ap.parse_args()
    report=inspect(a.bruce.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(report,indent=2)+"\n")
    print("Original firmware verified:",report["sha256_verified"])
    print("Raw tables:",json.dumps(report["raw_neighborhood"]))
    print("Exact refs:",json.dumps(report["exact_table_pointer_refs"]))
    print("Candidate signed class records:",json.dumps(report["record_layout_hypotheses"]))
    print("Wider PC literal refs:",json.dumps(report["wider_pc_literal_refs"]))
    if a.preview:
        for k,rows in report["code_windows"].items():
            print("WINDOW",k)
            for r in rows: print(r["pc"],r["m"],r["op"])
    print("No runtime EP0 callback or custom execution inferred.")

if __name__=="__main__":
    main()
