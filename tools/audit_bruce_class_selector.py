"""Trace signed OEM Bruce class-selector loops and startup table origins.

Offline-only; SHA-locked source firmware; no USB device or execution.
It is explicitly a candidate xref/assembly survey, not a proven runtime CFG.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE,ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET,ITCM_LENGTH,DATA_SOURCE_OFFSET,DATA_DESTINATION,DATA_END

BASE=ASSUMED_XIP_BASE
REGION_LIMIT=BASE+0xFF000
RECORD_START=0x60104B80
SEL4=0x60104BA0
RECORDS=[(1,[0x60054c7d,0x60054d09,0x60054a55]),
         (2,[0x60054875,0x600d0591,0x600d0333]),
         (4,[0x60055321,0x600d0ecb,0x600d0e59])]
WINDOWS={
 "class_registry_selection":(0x600551E0,0x60055320),
 "class_global_registrar":(0x60055320,0x60055350),
 "other_class_selector":(0x600549D0,0x60054A90),
 "class_startup_dispatch":(0x600D0A90,0x600D0C10),
 "class_get_configuration":(0x600D02B0,0x600D03D0),
}

def word(image, pc):
    if pc%4 or not BASE<=pc<=REGION_LIMIT-4:
        raise ValueError("Invalid signed XIP literal address")
    return struct.unpack_from("<I",image,pc-BASE)[0]

def decode(image,start,end):
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS)
    # Actual runtime uses combined mode, initialize separately to avoid conflation.
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str}
            for i in md.disasm(image[start-BASE:end-BASE],start)]

def find_class_selection_shapes(image, max_samples=30):
    """Near 'index << 4', compare & indirect method read in XIP stream."""
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    begin=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    out=[]
    for off in range(begin,0xFF000,0x10000):
        ins=list(md.disasm(image[off:min(off+0x10000,0xFF000)],BASE+off))
        for j,i in enumerate(ins):
            if not(i.mnemonic.startswith(("lsl","add")) and
                   ("#4" in i.op_str or "lsl #4" in i.op_str)):
                continue
            near=ins[max(0,j-16):min(len(ins),j+28)]
            has_indirect=any(x.mnemonic in ("blx","bx") and x.op_str.startswith("r") for x in near)
            has_load=any(x.mnemonic.startswith("ldr") and "[" in x.op_str for x in near)
            if not (has_indirect and has_load):continue
            out.append({
                "candidate_pc":hex(i.address),"instruction":i.mnemonic+" "+i.op_str,
                "surrounding":[hex(x.address)+" "+x.mnemonic+" "+x.op_str for x in near],
                "candidate_only":True,
            })
    return {"total_candidates":len(out),"examples":out[:max_samples],
            "limitations":"Linear XIP disassembly; lsl #4 may refer to unrelated structures or data."}

def startup_copy_targets(image):
    """Only the ordinary runtime initialized RAM region; no hidden RAM guess."""
    size=DATA_END-DATA_DESTINATION
    data=image[DATA_SOURCE_OFFSET:DATA_SOURCE_OFFSET+size]
    if len(data)!=size:
        raise ValueError("startup data copy missing")
    record={}
    for sel,ptrs in RECORDS:
        matches={}
        for val in [sel,*ptrs,RECORD_START,SEL4]:
            packed=struct.pack("<I",val)
            ofs=[at for at in range(0,len(data)-3,4)
                 if data[at:at+4]==packed]
            matches[hex(val)]=[hex(DATA_DESTINATION+x) for x in ofs[:24]]
        record[str(sel)]=matches
    return {"source_file_offset":hex(DATA_SOURCE_OFFSET),
            "destination_ram":hex(DATA_DESTINATION),
            "length_bytes":size,
            "matching_words_aligned":record,
            "nonzero_word_is_not_runtime_registration":True}

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact OEM signed Bruce SHA-256 and image size")
    rec=[]
    for i,(selector,methods) in enumerate(RECORDS):
        at=RECORD_START+i*16
        current=[word(image,at+offset) for offset in (0,4,8,12)]
        if current!=[selector,*methods]:
            raise ValueError("signed selector record drift at "+hex(at))
        rec.append({"start":hex(at),"selector":selector,
                    "thumb_methods":[hex(x) for x in methods]})
    x={
      "source":"Original OEM signed update; not live flash",
      "sha256_verified":True,"sha256":IMAGE_SHA256,
      "verified_record_candidates":rec,
      "specific_windows":{k:decode(image,a,b) for k,(a,b) in WINDOWS.items()},
      "selection_shapes":find_class_selection_shapes(image),
      "startup_copy_data_refs":startup_copy_targets(image),
      "real_object_writes_observed":False,
      "EP0_setup_reachability_proven":False,
      "hardware_IO":False,"flash_writes":False
    }
    return x

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--preview",action="store_true")
    a=p.parse_args()
    report=audit(a.bruce.read_bytes())
    if a.out:a.out.write_text(json.dumps(report,indent=2)+"\n")
    print("Original SHA OK:",report["sha256_verified"])
    print("Verified signed records:",json.dumps(report["verified_record_candidates"]))
    print("Startup-copy pointer matches:",json.dumps(report["startup_copy_data_refs"]))
    print("Class-shaped candidate count:",report["selection_shapes"]["total_candidates"])
    print("Class-shaped candidate examples:",json.dumps(report["selection_shapes"]["examples"][:15]))
    if a.preview:
        for name,rows in report["specific_windows"].items():
            print("WINDOW",name)
            for ins in rows: print(ins["pc"],ins["m"],ins["op"])
    print("No physical EP0 linkage or callback target inferred.")

if __name__=="__main__":
    main()
