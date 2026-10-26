"""Phase50 bounded original signed OEM owner pointer and field-reference census.

Static XIP literal occurrences and nearest signed Thumb decoder windows are
*references*, never proof of live RAM state. Owner 0x2000A2A8 and mode-2 gate
are verified against exact original signed Bruce SHA.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256,ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import DATA_DESTINATION,DATA_END
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_class_object_phase48 import raw_word
from tools.audit_bruce_usb_owner_survey_phase50 import validate_pins,KNOWN

BASE=ASSUMED_XIP_BASE
OWNER=0x2000A2A8
CORE=0x20004080
LITERALS={
 0x60071434:0x2000A824,
 0x60071438:OWNER,
}
PINS={
 0x60071408:("mov","r4, r0"),
 0x6007140A:("bne","#0x60071420"),
 0x60071414:("movs","r1, #3"),
 0x60071416:("ldr","r0, [pc, #0x20]"),
 0x6007141C:("b.w","#0x60060fe8"),
 0x60071428:("cmp","r4, #1"),
 0x6007142C:("moveq","r1, #2"),
 0x6007142E:("movne","r1, #1"),
 0x60061020:("cmp","r5, #2"),
 0x6006102A:("bne","#0x60061080"),
 0x6006102E:("bl","#0x60060f84"),
}
SPAN=((0x60071404,0x60071432),(0x6006101C,0x60061038))

def verify(actual):
    for pc,expected in PINS.items():
        if actual.get(pc)!=expected:
            raise ValueError("Phase50 fixed RAM owner/mode2 original code drift "+hex(pc)+": "+repr(actual.get(pc)))
    return len(PINS)

def nearby_exact_literals(image,targets=(OWNER,OWNER+4,OWNER+8,OWNER+12,CORE)):
    """Aligned 32-bit flash words only: no pretending byte census proves completeness."""
    out={}
    for target in targets:
        t=struct.pack("<I",target)
        offsets=[i for i in range(0,0xFF000-3,4) if image[i:i+4]==t]
        out[hex(target)]={
           "aligned_signed_literal_matches":len(offsets),
           "flash_address_words":[hex(BASE+i) for i in offsets[:40]],
           "nearby_linear_thumb_windows":[
             {"literal_at":hex(BASE+i),
              "preceding_candidate":[hex(q["pc"])+" "+q["m"]+" "+q["op"] for q in
                  decode(image,BASE+max(0,i-48),BASE+i)][:36]}
             for i in offsets[:12]]
        }
    return out

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("original signed Bruce OEM SHA-256 required")
    for addr,v in LITERALS.items():
        if raw_word(image,addr)!=v:
            raise ValueError("signed source owner address literal drift "+hex(addr))
    ins={}
    for a,b in SPAN:ins.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,a,b)})
    pins=verify(ins)
    assert OWNER>=DATA_END and OWNER>=DATA_DESTINATION
    return {
      "phase":50,"signed_original_SHA_verified":True,"semantic_pins":pins,
      "owner_literal":hex(OWNER),"owner_literal_site":"0x60071438",
      "mode_specific_signed_branch":{
        "caller_entry":"0x60071404",
        "owner_R0":"0x60071416 LDR R0,[PC,#0x20] reads 0x2000A2A8",
        "mode2_when_input_one":"0x60071428 CMP R4,#1; 0x6007142c MOVEQ R1,#2",
        "mode_transition":"0x6007141c B.W 0x60060fe8",
        "mode2_constructor_gate":"0x60061020 CMP R5,#2; 0x6006102a BNE skip; 0x6006102e BL 0x60060f84",
        "runtime_branch_executed":"UNVERIFIED"
      },
      "owner_class_config_offset":{
        "record_list_pointer":hex(OWNER+4),
        "dynamic_control_method":hex(OWNER+8),
        "class_record_count_byte":hex(OWNER+12),
        "notes":"Addresses only, not measured data values"
      },
      "owner_inside_initialised_signed_copy":False,
      "owner_literal_census":nearby_exact_literals(image),
      "live_class10_record_selection":"UNVERIFIED",
      "physical_USB_or_flash_access":False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args();z=audit(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(z,indent=2)+"\n")
    print("PHASE50 VERIFIED OWNER RAM AND MODE",json.dumps(z["mode_specific_signed_branch"]))
    print("PHASE50 ORIGINAL POINTER XREF CENSUS",json.dumps(z["owner_literal_census"]))
    print("PHASE50 ACTIVE OWNER CLASS LIST STILL UNMEASURED")
if __name__=="__main__":main()
