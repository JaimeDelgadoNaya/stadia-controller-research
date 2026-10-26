"""Trace candidate USB standard SETUP and class object callback provenance.

The sample is always the exact signed OEM Bruce update archive, not a live
device dump. Addresses are original XIP PC values. Direct BL scans are
candidate edges, not a proven reachability graph. Never touches USB.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode, callers_of_known, thumb_pointer_references

BASE=ASSUMED_XIP_BASE
FOCUS={
 "usb_standard_setup_early":(0x600D0B68,0x600D0C3C),
 "control_setup_parser":(0x600D0C3C,0x600D0DFC),
 "control_event_context":(0x600D0E58,0x600D0EC8),
 "usb_setup_dispatch_receiver":(0x600D0FB6,0x600D1060),
 "usb_event_class_bridge":(0x600CFC8E,0x600CFD35),
 "control_wrapper_group":(0x600D4300,0x600D4410),
 "control_bridge_literal_site":(0x600550D0,0x600551BC),
 "class_forwarder_literal_site":(0x60104B50,0x60104BC0),
 "control_request_dispatch":(0x600D07B0,0x600D0B70),
}
TARGETS={
 "setup_parser":0x600D0C3C,
 "setup_early":0x600D0BC8,
 "control_event":0x600D0E58,
 "usb_event_bridge":0x600CFC8E,
 "class_setup_processing":0x600D0D3E,
 "setup_dispatch_receiver":0x600D0FB6,
 "class_events_forwarder":0x600CFC1A,
}

def exact_xip_pointer_matches(image, targets, limit=35):
    """Find signed-image aligned or unaligned literal Thumb references."""
    out={}
    for name,pc in targets.items():
        raw=struct.pack("<I",pc|1)
        offsets=[]
        at=0
        while True:
            at=image.find(raw,at,0xFF000)
            if at<0:
                break
            offsets.append(at)
            at+=1
        out[name]={
            "thumb_pointer":hex(pc|1),
            "count":len(offsets),
            "file_offsets":[hex(o) for o in offsets[:limit]],
            "aligned_word_offsets":[hex(o) for o in offsets[:limit] if o%4==0],
            "ptr_appears_in_image_not_necessarily_in_callback_table":True,
        }
    return out

def control_input_loads(windows):
    """Report real offset-1 byte loads and nearby shape checks in focus windows."""
    output=[]
    for name,code in windows.items():
        for i,row in enumerate(code):
            if not row["m"].startswith("ldrb"):
                continue
            operands=row["op"].lower()
            if "#1]" not in operands and "#0x1]" not in operands:
                continue
            surroundings=code[max(0,i-10):min(len(code),i+14)]
            output.append({
                "region":name,
                "pc":hex(row["pc"]),
                "instruction":row["m"]+" "+row["op"],
                "nearby":[hex(x["pc"])+" "+x["m"]+" "+x["op"] for x in surroundings],
                "setup_brequest_proven":False,
                "provenance":"Local load only; base register still needs tracing to EP0 setup buffer.",
            })
    return output

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact SHA-pinned signed Bruce image")
    windows={name:decode(image,start,end) for name,(start,end) in FOCUS.items()}
    xrefs=callers_of_known(image,TARGETS,max_examples=20)
    data={
        "original_signed_bruce_sha256":IMAGE_SHA256,
        "sha256_verified":True,
        "target_candidates":{name:hex(target) for name,target in TARGETS.items()},
        "direct_bl_xrefs":xrefs,
        "thumb_pointer_refs":exact_xip_pointer_matches(image,TARGETS),
        "control_byte_plus_one_loads":control_input_loads(windows),
        "bounded_code_windows":windows,
        "EP0_class_callback_runtime_pointer":"UNKNOWN",
        "host_brequest_0x81_83_84_verified":"NO",
        "connected_device":False,
        "usb_transfers":False,
        "writes":False,
        "limits":["Signed update image not installed flash readback",
                  "XIP Thumb linear windows may include embedded literal data",
                  "Class/object pointers and indirect control transfers unknown",
                  "No host-to-handler reachability or arbitrary execution established"],
    }
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--verbose",action="store_true")
    a=p.parse_args()
    result=audit(a.bruce.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("SIGNED BRUCE SHA VERIFIED",result["sha256_verified"])
    print("XIP DIRECT CALLER SITES",json.dumps({
        k:[z["callsite"] for z in v]
        for k,v in result["direct_bl_xrefs"].items()
    }))
    print("THUMB POINTER REF OFFSETS",json.dumps({
        k:{"count":v["count"],"file_offsets":v["file_offsets"]}
        for k,v in result["thumb_pointer_refs"].items()
    }))
    print("BYTE OFFSET +1 LOADS",json.dumps([
        {"region":q["region"],"pc":q["pc"],"instruction":q["instruction"]}
        for q in result["control_byte_plus_one_loads"]
    ]))
    if a.verbose:
        for name in ("control_bridge_literal_site","class_forwarder_literal_site","control_request_dispatch"):
            print("WINDOW",name)
            for row in result["bounded_code_windows"][name]:
                print(hex(row["pc"]),row["m"],row["op"])

if __name__=="__main__":
    main()
