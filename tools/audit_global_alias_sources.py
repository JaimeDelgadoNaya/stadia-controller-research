"""Phase 21: offline global-RAM-pointer xrefs and a bounded constructor alias chain.

Checks one SHA-256-verified private 128-KiB Stadia bootloader A image.
No USB, flash, eFuse, controller access or code execution. Raw instruction
candidates are not proof of dynamic reachability or absence of setters.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 0x20000
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
GLOBAL = 0x20008B78
SCAN_START, SCAN_END = 0x1000, 0x14F00
FIELD_WRITES = {
    "bulk_in_handler": (0xBB50, 0x5F8, "c4f8f835"),
    "bulk_in_context": (0xBB6C, 0x5FC, "c4f8fc55"),
    "bulk_out_handler": (0xBB5A, 0x600, "c4f80036"),
    "bulk_out_context": (0xBB70, 0x604, "c4f80456"),
}
ANCHORS = {
    0xC0B2: "0248",           # ldr r0, literal 0x6080c0bc
    0xC0B4: "fff704fd",       # bl 0x6080bac0
    0xBAC4: "0446",           # mov r4,r0
    0x9E6A: "0848",           # ldr r0, global
    0x9E6E: "d0f8f035",       # ldr.w r3,[r0,#0x5f0]
    0x9E76: "d0f8f405",       # ldr.w r0,[r0,#0x5f4]
    0x9EB8: "324b",           # ldr r3, global
    0x9EBE: "93f8c436",       # ldrb.w r3,[r3,#0x6c4]
    **{off: encoded for off, _, encoded in FIELD_WRITES.values()},
}

def word(image, off):
    return struct.unpack_from("<I", image, off)[0]

def fmt(n):
    return f"0x{n:08x}"

def decode_bl(image, off):
    """Decode Thumb-2 BL immediate; reject unrelated instruction forms."""
    h1, h2 = struct.unpack_from("<HH", image, off)
    if (h1 & 0xF800) != 0xF000 or (h2 & 0xD000) != 0xD000:
        raise ValueError("Expected Thumb BL")
    s, j1, j2 = (h1 >> 10)&1, (h2 >> 13)&1, (h2 >> 11)&1
    i1, i2 = 1^(j1^s), 1^(j2^s)
    imm = (s<<24)|(i1<<23)|(i2<<22)|((h1&1023)<<12)|((h2&2047)<<1)
    return (BASE+off+4+(imm-(1<<25) if s else imm))&0xFFFFFFFF

def literal_words(image, target=GLOBAL):
    return {i for i in range(0,len(image)-3,4) if word(image,i)==target}

def literal_load_candidates(image, words, start=SCAN_START, end=SCAN_END):
    """Decode Thumb16 and Thumb32 PC-relative loads at halfword positions.

    Halfword scanning can overlap data/literal pools. Report CANDIDATES
    without assuming reachable instructions or complete control flow.
    """
    if not 0 <= start < end <= len(image) or (start|end)&1:
        raise ValueError("Invalid aligned scan bounds")
    result=[]
    for off in range(start,end-1,2):
        h1=struct.unpack_from("<H",image,off)[0]
        alternatives=[]
        if h1&0xF800==0x4800:
            alternatives.append(((h1>>8)&7,((BASE+off+4)&~3)+4*(h1&255),
                                 image[off:off+2].hex(),"Thumb16 LDR literal"))
        if off+4<=end and h1 in (0xF8DF,0xF85F):
            h2=struct.unpack_from("<H",image,off+2)[0]
            if (h2>>12)!=15:
                d=(h2&0xFFF)*(1 if h1==0xF8DF else -1)
                alternatives.append((h2>>12,((BASE+off+4)&~3)+d,
                                     image[off:off+4].hex(),"Thumb32 LDR literal"))
        for reg,target,enc,kind in alternatives:
            if target-BASE in words:
                result.append({"at":fmt(BASE+off),"literal":fmt(target),
                               "register":f"r{reg}","encoding":enc,
                               "kind":kind,"reachable":"NOT ESTABLISHED"})
    return sorted(result,key=lambda x:(x["at"],x["literal"]))

def audit(image, expected_sha256=SHA256, strict_counts=True):
    if len(image)!=SIZE:
        raise ValueError("Expected 131072-byte bootloader A")
    sha=hashlib.sha256(image).hexdigest()
    if sha!=expected_sha256:
        raise ValueError("Unexpected SHA-256; cannot analyze this build")
    words=literal_words(image)
    candidates=literal_load_candidates(image, words)
    if strict_counts and (len(words),len(candidates))!=(21,29):
        raise ValueError("Known bootloader literal census drifted")
    for off,hexbytes in ANCHORS.items():
        if image[off:off+len(hexbytes)//2]!=bytes.fromhex(hexbytes):
            raise ValueError(f"Instruction anchor mismatch at {fmt(BASE+off)}")
    if word(image,0xC0BC)!=GLOBAL:
        raise ValueError("Constructor does not use expected global")
    if not any(c["at"]==fmt(BASE+0xC0B2) and c["register"]=="r0" and
               c["literal"]==fmt(BASE+0xC0BC) for c in candidates):
        raise ValueError("Constructor literal load not found")
    dst=decode_bl(image,0xC0B4)
    if dst!=BASE+0xBAC0:
        raise ValueError("BL target does not match constructor")
    fields=[{"name":name,"ram_address":fmt(GLOBAL+disp),
             "constructor_store_at":fmt(BASE+off),
             "base_register":"r4 (MOV from argument r0)"}
            for name,(off,disp,_) in FIELD_WRITES.items()]
    return {
        "phase":21,"build":169429,"sha256_verified":True,"sha256":sha,
        "hardware_access":False,"usb_transfers":False,"flash_operations":False,
        "global_pointer_sources":{
            "ram_global":fmt(GLOBAL),"aligned_literal_words":len(words),
            "literal_addresses":[fmt(BASE+x) for x in sorted(words)],
            "pc_relative_load_candidates":len(candidates),
            "loads":candidates,
            "scan_end_exclusive":fmt(BASE+SCAN_END),
            "limitation":"Candidate Thumb decodings, NOT a whole-program CFG or reachability proof"},
        "verified_conditional_alias_chain":{
            "literal_at":"0x6080c0bc","load_into_r0":"0x6080c0b2",
            "bl_site":"0x6080c0b4","bl_target":fmt(dst),
            "constructor_argument_copy":"0x6080bac4 MOV r4,r0",
            "constructor_stores":fields,
            "meaning":"ONE direct static alias-to-initializer chain, not later callback registration"},
        "readonly_vendor_examples":[
            {"address":"0x60809e6a","uses":"reads global+0x5f0 and +0x5f4"},
            {"address":"0x60809eb8","uses":"reads global+0x6c4 for setup state"}],
        "other_aliases":"NOT FULLY RESOLVED",
        "later_callback_mutation":"NOT DEMONSTRATED OR EXCLUDED",
        "host_bulk_out_to_parser":"NOT DEMONSTRATED",
        "host_to_flash_write":"NOT DEMONSTRATED",
        "hab_closed_bypass":"NOT DEMONSTRATED",
        "custom_execution":"NOT DEMONSTRATED",
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    result=json.dumps(audit(a.bootloader.read_bytes()),indent=2)+"\n"
    if a.out:
        a.out.write_text(result,encoding="utf-8")
    else:
        print(result,end="")

if __name__=="__main__":
    main()
