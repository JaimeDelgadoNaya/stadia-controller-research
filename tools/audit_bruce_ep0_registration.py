"""Read-only original Bruce EP0 slot registration reconnaissance.

Investigates initialization of the 12-byte endpoint callback entries used
by the verified SETUP event dispatcher at XIP 0x600D0FB6. Only scans a
SHA-pinned public signed update image; never opens any USB device.
Linear disassembly produces *candidate* BL xrefs, not a CFG proof.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

BASE=ASSUMED_XIP_BASE
REGION_START=0x600D0B00
REGION_END=0x600D1200
FOCUSED_START=0x600D0D40
FOCUSED_END=0x600D0FC0
DISPATCHER=0x600D0FB6
ENDPOINT_STRIDE=12
EP0_OUT_INDEX=0
EP0_IN_INDEX=1


def decode(image, start, end):
    """Thumb instructions in XIP-addressed bytes; no reachability claim."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    if not BASE <= start < end <= BASE+0xFF000:
        raise ValueError("disassembly outside signed XIP application")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":i.address,"m":i.mnemonic,"op":i.op_str}
            for i in md.disasm(image[start-BASE:end-BASE],start)]


def direct_call_target(row):
    if row["m"] not in ("bl","b.w"):
        return None
    op=row["op"]
    if not op.startswith("#"):
        return None
    try:
        return int(op[1:],0)
    except ValueError:
        return None


def candidate_calls(image, *, max_per_target=8):
    # The XIP region follows startup's relocated ITCM code. Avoid that
    # source image and its misleading stored PC-relative branch targets.
    initial=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    hits=Counter()
    exemplars={}
    boundary=0xFF000
    for off in range(initial,boundary,0x2000):
        rows=decode(image,BASE+off,BASE+min(off+0x2000,boundary))
        for k,row in enumerate(rows):
            if row["m"]!="bl":
                continue
            target=direct_call_target(row)
            if target is None or not REGION_START<=target<REGION_END:
                continue
            key=hex(target)
            hits[key]+=1
            if len(exemplars.setdefault(key,[]))<max_per_target:
                exemplars[key].append({
                    "callsite":hex(row["pc"]),
                    "preceding":[{"pc":hex(q["pc"]),"ins":q["m"]+" "+q["op"]}
                                 for q in rows[max(0,k-7):k]],
                    "method":"linear Thumb decode, unverified as executable call path",
                })
    return {"counts":dict(sorted(hits.items(),key=lambda item:int(item[0],16))),
            "examples":exemplars,
            "limitations":"Linear XIP-only decode may miss true calls and decode tables as instructions; indirect BLX not found."}



def candidate_slot_writers(image, limit=40):
    """Search nearby XIP code for 12-byte indexed RAM slot write shapes.

    Ranks direct contiguous MLA/LSL+STR snippets. These can be stores to
    unrelated 12-byte structures or data interpreted as code.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    import re
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    candidates=[]
    for offset in range((ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1,0xFF000,0x2000):
        ins=list(dec.disasm(image[offset:min(offset+0x2000,0xFF000)],BASE+offset))
        for j,cur in enumerate(ins):
            if cur.mnemonic!="mla":
                continue
            # A multiply-add stride is suggestive, not sufficient.
            before=ins[max(0,j-10):j]
            after=ins[j+1:min(j+23,len(ins))]
            near_before=[(x.address,x.mnemonic,x.op_str) for x in before]
            stride12=any(x.mnemonic.startswith(("mov","movs")) and
                         re.search(r"#(?:0xc|12)\b",x.op_str)
                         for x in before)
            stores=[x for x in after if x.mnemonic.startswith(("str","stm"))]
            pair_writes=[x for x in stores if x.mnemonic.startswith(("strd","stm")) or
                         re.search(r"\[r\d+, #0x(?:c|10|18|1c)\]",x.op_str)]
            if not stride12 or not pair_writes:
                continue
            points=0
            points+=4 if stride12 else 0
            points+=2*len(pair_writes)
            points+=1 if any(x.mnemonic=="blx" for x in after) else 0
            candidates.append({
                "pc":hex(cur.address),
                "score_heuristic":points,
                "nearby_store_pcs":[hex(x.address) for x in pair_writes],
                "pre":[hex(a)+" "+m+" "+o for a,m,o in near_before[-7:]],
                "post":[hex(x.address)+" "+x.mnemonic+" "+x.op_str for x in after[:17]],
                "USB_slot_registration_proven":False,
            })
    candidates.sort(key=lambda row:(-row["score_heuristic"],int(row["pc"],16)))
    return {
        "total_candidate_regions":len(candidates),
        "top":candidates[:limit],
        "truncated":len(candidates)>limit,
        "method_limit":"Linear Thumb decoding, heuristic stride-12/store proximity only; no pointer alias or reachable CFG proof.",
    }


def initialized_data_callbacks(image, limit=70):
    """Inspect startup-copied RAM data for potential signed Thumb pointers.

    This does not imply any pointer is in endpoint slots 0/1. Class
    callbacks can also be installed dynamically after boot.
    """
    from tools.audit_app_usb_dispatch import DATA_SOURCE_OFFSET, DATA_DESTINATION, DATA_END
    import struct
    copied=image[DATA_SOURCE_OFFSET:DATA_SOURCE_OFFSET+DATA_END-DATA_DESTINATION]
    matches=[]
    for at in range(0,len(copied)-3,4):
        v=struct.unpack_from("<I",copied,at)[0]
        if v&1 and (BASE <= (v&~1) < BASE+0xFF000 or
                    0 <= (v&~1) < ITCM_LENGTH):
            matches.append({
                "copied_to_ram":hex(DATA_DESTINATION+at),
                "source_offset":hex(DATA_SOURCE_OFFSET+at),
                "thumb_pointer":hex(v),
                "usb_relevant_range":0x600D0000 <= (v&~1) < 0x600D6000,
            })
    return {
        "total_thumb_pointer_shaped_words":len(matches),
        "near_usb_xip_count":sum(1 for row in matches if row["usb_relevant_range"]),
        "usb_related_potential_pointers":[row for row in matches if row["usb_relevant_range"]][:limit],
        "first_general_pointer_examples":matches[:min(limit,20)],
        "original_image_matches_runtime_ep0_slot":"NOT VERIFIED",
    }

def resolve_known_registrar_literals(image):
    """Decode PC-relative constant words in *specific* verified XIP callsites.

    Literal bytes at 0x600547a0/a4/a8 and 0x60054870 must not be treated
    as instructions. A literal value can designate a signed handler without
    proving the branch is taken or EP0 uses this entry.
    """
    import struct
    refs=[
        {"load_pc":0x60054736,"reg":"r7","disp":0x68},
        {"load_pc":0x60054738,"reg":"r8","disp":0x68},
        {"load_pc":0x6005473C,"reg":"sb","disp":0x68},
        {"load_pc":0x6005480E,"reg":"r8","disp":0x60},
    ]
    results=[]
    for ref in refs:
        literal=((ref["load_pc"]+4)&~3)+ref["disp"]
        if not BASE <= literal < BASE+0xFF000:
            raise ValueError("PC-relative reference out of image")
        value=struct.unpack_from("<I",image,literal-BASE)[0]
        valid_thumb=bool(value&1) and BASE<= (value&~1)<BASE+0xFF000
        item={"load_pc":hex(ref["load_pc"]),
              "register":ref["reg"],"literal_at":hex(literal),
              "pointer":hex(value),"signed_xip_thumb":valid_thumb,
              "registration_path": "endpoint_descriptor_loop" if ref["load_pc"]!=0x6005480E
                                    else "alternate_endpoint_descriptor_loop",
              "callback_currently_installed_in_EP0":"UNVERIFIED"}
        if valid_thumb:
            target=value&~1
            item["target_preview"]=[
                {"pc":hex(row["pc"]),"m":row["m"],"op":row["op"]}
                for row in decode(image,target,min(target+112,BASE+0xFF000))[:40]
            ]
        results.append(item)
    return results


def thumb_pointer_references(image, pointers):
    """All aligned literal references to selected original Thumb functions."""
    import struct
    result={}
    for name,pointer in pointers.items():
        needle=struct.pack("<I",pointer)
        offsets=[off for off in range(0,0xFF030-3,4)
                 if image[off:off+4]==needle]
        result[name]={
            "thumb_pointer":hex(pointer),
            "aligned_word_reference_count":len(offsets),
            "aligned_word_offsets":[hex(i) for i in offsets[:70]],
            "candidate_table_or_literal_only":True
        }
    return result


def callers_of_known(image, named_targets, max_examples=20):
    """XIP direct BL caller census, not a full interprocedural CFG."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    wanted={v:k for k,v in named_targets.items()}
    found={k:[] for k in named_targets}
    start=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    for off in range(start,0xFF000,0x2000):
        ins=list(md.disasm(image[off:min(off+0x2000,0xFF000)],BASE+off))
        for idx,row in enumerate(ins):
            if row.mnemonic!="bl" or not row.op_str.startswith("#"):
                continue
            try:
                val=int(row.op_str[1:],0)
            except ValueError:
                continue
            if val not in wanted:
                continue
            name=wanted[val]
            if len(found[name])>=max_examples:
                continue
            found[name].append({
                "callsite":hex(row.address),
                "before":[hex(i.address)+" "+i.mnemonic+" "+i.op_str
                          for i in ins[max(0,idx-12):idx]],
                "after":[hex(i.address)+" "+i.mnemonic+" "+i.op_str
                         for i in ins[idx+1:idx+5]],
                "live_call_edge":"UNVERIFIED linear decode",
            })
    return found


REGISTRAR_ANCHORS={
    0x600D10B8:("push","{r4, r5, r6}"),
    0x600D10C0:("ldrb","r4, [r1, #2]"),
    0x600D10C2:("and","r5, r4, #0xf"),
    0x600D10C6:("cmp","r5, #7"),
    0x600D10D0:("orr.w","r3, r3, r5, lsl #1"),
    0x600D10D4:("movs","r5, #0xc"),
    0x600D10D6:("mla","r3, r5, r3, r0"),
    0x600D10DA:("str","r2, [r3, #0x10]"),
    0x600D10DE:("str","r4, [r3, #0xc]"),
    0x600D10E0:("strb","r2, [r3, #0x14]"),
    0x600D10E8:("b.w","#0x600d0ede"),
    0x60054782:("bl","#0x600d10b8"),
    0x60054850:("bl","#0x600d10b8"),
    0x60054774:("str.w","sb, [sp, #0xc]"),
    0x60054794:("str.w","r8, [sp, #0xc]"),
    0x6005479A:("str","r7, [sp, #0xc]"),
    0x6005484C:("strd","r8, r4, [sp, #0xc]"),
    0x600D1122:("strd","r2, r2, [r3, #0xc]"),
}
CALLBACK_THUMB_POINTER_ANCHORS={
    0x600547A0:0x600CFC71,
    0x600547A4:0x600CFC35,
    0x600547A8:0x600CFC53,
    0x60054870:0x600CFC1B,
}

def validate_registration_anchors(decoded,pointers):
    for pc,semantic in REGISTRAR_ANCHORS.items():
        if decoded.get(pc)!=semantic:
            raise ValueError("Original EP0 endpoint registration semantic drift: "+hex(pc))
    for pc,ptr in CALLBACK_THUMB_POINTER_ANCHORS.items():
        if pointers.get(pc)!=ptr:
            raise ValueError("Original endpoint literal pointer drift: "+hex(pc))
    return True


def audit(image, *, include_focused=False):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed Bruce update sample required (SHA256 and size)")
    calls=candidate_calls(image)
    focused=decode(image,FOCUSED_START,FOCUSED_END)
    origin_code=decode(image,0x600D10B8,0x600D1134)+decode(image,0x60054728,0x60054858)
    anchored={row["pc"]:(row["m"],row["op"]) for row in origin_code}
    resolved=resolve_known_registrar_literals(image)
    literals={int(item["literal_at"],16):int(item["pointer"],16) for item in resolved}
    validate_registration_anchors(anchored,literals)
    stores=[x for x in focused if x["m"].startswith(("str","stm"))]
    return {
        "oem_signed_image_sha256_verified":True,
        "original_sha256":IMAGE_SHA256,
        "dispatcher":hex(DISPATCHER),
        "entry_byte_stride":ENDPOINT_STRIDE,
        "endpoint_slot_formula":"2*(endpoint & 0x0f) + ((endpoint>>7)&1)",
        "ep0_out_slot_index":EP0_OUT_INDEX,
        "ep0_in_slot_index":EP0_IN_INDEX,
        "ep0_out_callback_offset_from_object":hex(0x0c),
        "ep0_in_callback_offset_from_object":hex(0x0c+ENDPOINT_STRIDE),
        "candidate_function_calls_to_usb_core":calls,
        "candidate_slot_writers":candidate_slot_writers(image),
        "registration_handler_literals":resolved,
        "original_registration_semantic_anchors_verified":True,
        "registrar_pointer_refs":thumb_pointer_references(image,{
            "device_endpoint_registration_api":0x600D10B9,
            "descriptor_loop_function":0x60054729,
            "alternate_endpoint_loop_function":0x600547AD,
            "signed_setup_event_dispatcher":0x600D0FB7,
        }),
        "direct_callers_of_descriptor_loops":callers_of_known(image,{
            "descriptor_loop_function":0x60054728,
            "alternate_endpoint_loop_function":0x600547AC,
        }),
        "initialized_data_pointer_census":initialized_data_callbacks(image),
        "endpoint_callback_registrar_code": [
            {"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
            for x in decode(image,0x600D10B8,0x600D10F6)],
        "class_dispatch_windows":{
            "class_event_forwarders":[
                {"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
                for x in decode(image,0x600CFC1A,0x600CFC8E)],
            "class_configuration_event":[
                {"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
                for x in decode(image,0x600CFD28,0x600CFDE0)],
            "usb_class_object_initialization":[
                {"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
                for x in decode(image,0x600D0340,0x600D03BE)],
        },
        "registration_caller_context": [
            {"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
            for x in decode(image,0x600546C0,0x60054880)],
        "usb_core_window":
            [{"pc":hex(i["pc"]),"m":i["m"],"op":i["op"]} for i in focused]
            if include_focused else [],
        "candidate_stores_count_in_window":len(stores),
        "verified_registration":{
            "api":"0x600d10b8",
            "slot_offset_callback":hex(0x0c),
            "slot_offset_context":hex(0x10),
            "per_endpoint_stride":12,
            "input_endpoint_address_from_structure":"+2",
            "callers":["0x60054782","0x60054850"],
            "callback_thumb_targets":[hex(x) for x in CALLBACK_THUMB_POINTER_ANCHORS.values()],
            "callback_targets_are_class_forwarders":"Likely, inferred from indirect jump to a class object's callback; actual class target unknown",
            "de_registration_slot_zeroer":"0x600d1122 (slot pair zeroed under guard)",
            "runtime_ep0_entries":"NOT IDENTIFIED",
        },
        "ep0_runtime_callback_pointer":"NOT IDENTIFIED",
        "ep0_setup_class_brequest_receiver":"NOT IDENTIFIED",
        "host_to_custom_execution":"NOT DEMONSTRATED",
        "physical_device_access":False,
        "firmware_writes":False,
    }


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("image",type=Path)
    a.add_argument("--out",type=Path)
    a.add_argument("--show-focused",action="store_true")
    p=a.parse_args()
    result=audit(p.image.read_bytes(),include_focused=p.show_focused)
    if p.out:
        p.out.write_text(json.dumps(result,indent=2)+"\n")
    print("ORIGINAL SIGNED IMAGE VERIFIED:",result["oem_signed_image_sha256_verified"])
    print("REGISTRAR:",result["verified_registration"]["api"],
          "slot stride",result["verified_registration"]["per_endpoint_stride"],
          "semantic anchors",result["original_registration_semantic_anchors_verified"])
    print("DIRECT REGISTRAR CALLS:",result["verified_registration"]["callers"])
    print("ORIGINAL REGISTERED FORWARDER CONSTANTS:",
          [row["pointer"] for row in result["registration_handler_literals"]])
    print("CLASS CALLBACK FORWARDERS ARE INDIRECT; EP0 RUNTIME SLOT UNKNOWN.")
    print("DESCRIPTOR LOOP DIRECT XIP CALLS:",{
          k:[q["callsite"] for q in v]
          for k,v in result["direct_callers_of_descriptor_loops"].items()})
    print("CANDIDATE STRIDE-12 STORE REGIONS:",
          result["candidate_slot_writers"]["total_candidate_regions"])
    print("INIT-DATA USB-AREA THUMB-SHAPED POINTERS:",
          result["initialized_data_pointer_census"]["near_usb_xip_count"])
    print("FIRMWARE WRITES: none (offline parser)")
    if p.show_focused:
        for ins in result["usb_core_window"]:
            print("FOCUSED",ins["pc"],ins["m"],ins["op"])


if __name__=="__main__":
    main()
