"""Pin actual USB SETUP field triads and class bRequest forwarding in Bruce.

Read-only, exact signed OEM SHA256. EP0 runtime callback and native console
compatibility are not inferred from static code. ARM literals are not code.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode

BASE=ASSUMED_XIP_BASE
ANCHORS={
 0x600D08EE:("mov","r4, r1"),
 0x600D090E:("ldrb","r3, [r4, #1]"),
 0x600D091A:("ldrb","r3, [r4]"),
 0x600D091C:("ands","r3, r3, #0x1f"),
 0x600D0922:("ldrh","r3, [r4, #2]"),
 0x600D0958:("ldrh","r1, [r4, #4]"),
 0x600D0D3C:("ldr","r3, [r2]"),
 0x600D0D3E:("ldrb","r0, [r3]"),
 0x600D0D40:("and","r0, r0, #0x1f"),
 0x600D0D44:("cmp","r0, #1"),
 0x600D0D4A:("ldrb","r2, [r3, #4]"),
 0x600D0D50:("ldrb","r2, [r3, #1]"),
 0x600D0D52:("subs","r2, #1"),
 0x600D0D54:("cmp","r2, #0xa"),
 0x600D0D58:("tbb","[pc, r2]"),
 0x600D0EA2:("ldr","r1, [r2]"),
 0x600D0EA4:("ldrb","r3, [r1]"),
 0x600D0EA6:("and","r3, r3, #0x1f"),
 0x600D0EAA:("cmp","r3, #1"),
 0x600D0EAE:("ldrb","r5, [r0, #0xd]"),
 0x600D0EB0:("ldrb","r4, [r1, #4]"),
 0x600D0EB2:("cmp","r5, r4"),
 0x600D0EB6:("ldr","r3, [r0, #4]"),
 0x600D0EB8:("ldrb","r1, [r1, #1]"),
 0x600D0EBA:("ldr","r3, [r3]"),
 0x600D0EBE:("bx","r3"),
 0x600CFCD4:("ldr","r2, [r3, #8]"),
 0x600CFCDA:("ldrb","r3, [r3, #1]"),
 0x600CFCDC:("and","r3, r3, #0x30"),
}

WINDOWS=[
 (0x600D08E8,0x600D097C),
 (0x600D0D3C,0x600D0D5C),
 (0x600D0EA2,0x600D0EC0),
 (0x600CFCD4,0x600CFCE4),
]

def check_anchors(rows):
    for pc,expect in ANCHORS.items():
        if rows.get(pc)!=expect:
            raise ValueError("Signed Bruce USB SETUP semantic drift at "+hex(pc))
    return True

def literal_table(image,start=0x60104B88,end=0x60104BE0):
    """Flash data: decode little-endian words, never Thumb instructions."""
    if not(BASE<=start<end<=BASE+0xFF000) or (start|end)&3:
        raise ValueError("invalid literal table bounds")
    return [{"pc":hex(p),"word":hex(struct.unpack_from("<I",image,p-BASE)[0])}
            for p in range(start,end,4)]

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact original Bruce signed image SHA256 and size required")
    rows={}
    for lo,hi in WINDOWS:
        rows.update({r["pc"]:(r["m"],r["op"]) for r in decode(image,lo,hi)})
    check_anchors(rows)
    table=literal_table(image)
    matches=[q for q in table if q["pc"]=="0x60104bac"]
    if len(matches)!=1 or matches[0]["word"]!="0x600d0e59":
        raise ValueError("Original class dispatch function table pointer drift")
    return {
        "sha256_verified":True,
        "sha256":IMAGE_SHA256,
        "original_assembly_semantic_anchors_verified":len(ANCHORS),
        "setup_fields_0x600d08e8":{
            "argument_to_base":"0x600d08ee MOV R4,R1",
            "request_byte_plus_one":"0x600d090e",
            "bmRequestType_plus_zero":"0x600d091a",
            "wValue_plus_two":"0x600d0922",
            "wIndex_plus_four":"0x600d0958",
            "status":"SETUP-consistent field triad in original signed code, physical EP0 caller unverified"
        },
        "standard_interface_dispatch":{
            "entry_branch":"0x600d0d3c",
            "source_pointer":"0x600d0d3c LDR R3,[R2]",
            "recipient_check":"0x600d0d3e..0x600d0d46 bmRequestType&0x1F == 1",
            "interface_index":"0x600d0d4a request buffer offset +4",
            "request_byte":"0x600d0d50 request buffer offset +1",
            "branch_table":"0x600d0d52..0x600d0d58 request ids 1..11",
            "this_branch_reaches_request_0x81_0x83_0x84":False,
        },
        "class_request_forwarding":{
            "event_handler":"0x600d0e58",
            "branch":"0x600d0ea2",
            "request_pointer":"0x600d0ea2 LDR R1,[R2]",
            "bmRequestType":"0x600d0ea4 LDRB R3,[R1]",
            "recipient_guard":"0x600d0ea6..0x600d0eaC bmRequestType&0x1F == 1",
            "interface_check":"0x600d0eae..0x600d0eb4 object+0x0D versus buffer+4",
            "request_byte":"0x600d0eb8 LDRB R1,[R1,#1]",
            "indirect_class_target":"0x600d0eb6 LDR R3,[R0,#4]; 0x600d0eba LDR R3,[R3]; 0x600d0ebe BX R3",
            "host_specific_class_requests_0x81_0x83_0x84":"NOT PROVEN TO REACH TARGET",
            "class_callback_pointer_contents":"UNKNOWN",
            "host_supplied_callback_address":False,
        },
        "descriptor_byte_load_contrast":{
            "region":"0x600cfcd4..0x600cfce2 reads endpoint descriptor entry byte +1 and masks 0x30",
            "not_a_proven_ep0_brequest":True,
        },
        "static_control_handler_table_words":table,
        "control_handler_thumb_word_at_0x60104bac":"0x600d0e59",
        "literal_word_proves_live_callback_registration":False,
        "physical_controller_access":False,"usb_packets_sent":False,"flash_written":False,
        "code_execution_or_bypass_demonstrated":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("SIGNED ORIGINAL SETUP ANCHORS VERIFIED:",result["original_assembly_semantic_anchors_verified"])
    print("STANDARD SETUP request dispatch 1..11:",result["standard_interface_dispatch"]["branch_table"])
    print("CLASS bRequest TO INDIRECT CALLBACK:",result["class_request_forwarding"]["indirect_class_target"])
    print("CLASS TABLE WORD",result["control_handler_thumb_word_at_0x60104bac"])
    print("HOST REQUEST 0x81/0x83/0x84 REACHABILITY: UNVERIFIED")
    print("NO DEVICE IO, FLASH WRITES, INSTALLABLE FIRMWARE OR BYPASS.")

if __name__=="__main__":
    main()
