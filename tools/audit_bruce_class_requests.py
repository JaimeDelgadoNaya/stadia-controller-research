"""Read-only discovery of candidate *normal-mode* Bruce class USB handlers.

Pins the original signed Bruce update image. Reports surrounding Thumb code
for known vendor-component string references, plus byte-immediate comparisons.
This is *reconnaissance*, not a proven bRequest dispatch graph or device test.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

# Known literal xrefs to "usb_device_vendor.cc" (original signed sample).
VENDOR_REFS = (0x21504, 0x215B4)
VENDOR_STRING = b"usb_device_vendor.cc"
VENDOR_STRING_OFFSET = 0xDE054
XIP_BASE = ASSUMED_XIP_BASE

CANDIDATE_RANGES = (
    ("vendor_component_first_callsite_context", 0x21440, 0x21504),
    ("vendor_component_second_callsite_context", 0x21540, 0x215B4),
    ("nearby_vendor_dispatch", 0x215B8, 0x21770),
    ("normal_mode_known_message_parser", 0x18B64, 0x18C00),
    ("focused_candidate_0x81", 0x30C20, 0x30D24),
    ("focused_candidate_0x84", 0xB4B20, 0xB4B88),
)

def disassemble(data, start, end, *, max_output=160):
    """Byte-stream Thumb preview; literal pools/embedded data are not code."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    if not (0 <= start < end <= len(data)):
        raise ValueError("invalid disassembly bounds")
    instructions=[]
    for ins in md.disasm(data[start:end],XIP_BASE+start):
        instructions.append({"address":hex(ins.address),
                             "mnemonic":ins.mnemonic,"operands":ins.op_str})
        if len(instructions)>=max_output:
            break
    return instructions

def classify_request_compare(mnemonic, operands):
    # A CMP or CBZ immediate is only a candidate. It might compare unrelated
    # values or synthesized fields rather than a USB bRequest.
    m=mnemonic.lower()
    if not m.startswith("cmp"):
        return None
    items=operands.split(",")
    if len(items)!=2 or not items[1].strip().startswith("#"):
        return None
    try:
        number=int(items[1].strip()[1:],0)
    except ValueError:
        return None
    return number if number in (0x81,0x83,0x84) else None

def census_imm_comparisons(data, per_request_limit=30):
    """Coarse entire-signed-app literal CMP census; not reachable CFG.

    Decode chunks of 0x2000 bytes, including the copied ITCM image and XIP
    application separately. The copied ITCM half is reported using source
    offsets; PCs printed from its XIP bytes are *not* relocated runtime PCs.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    zones=(
        ("ITCM_source_NOT_runtime_PC",ITCM_SOURCE_OFFSET,
         ITCM_SOURCE_OFFSET+ITCM_LENGTH),
        ("XIP_signed_application", ITCM_SOURCE_OFFSET+ITCM_LENGTH,0xFF000)
    )
    results={hex(v):{"count_in_linear_decode":0,"examples":[]} for v in (0x81,0x83,0x84)}
    for kind,start,end in zones:
        for chunk in range(start,end,0x2000):
            decoded=list(md.disasm(data[chunk:min(chunk+0x2000,end)],XIP_BASE+chunk))
            for i,ins in enumerate(decoded):
                value=classify_request_compare(ins.mnemonic,ins.op_str)
                if value is None:
                    continue
                row=results[hex(value)]
                row["count_in_linear_decode"]+=1
                if len(row["examples"])>=per_request_limit:
                    continue
                context=decoded[max(0,i-6):i+5]
                row["examples"].append({
                    "file_offset":hex(ins.address-XIP_BASE),
                    "decoded_address_not_necessarily_runtime":hex(ins.address),
                    "zone":kind,
                    "preceding_byte_load":[
                        {"pc":hex(prev.address),"ins":prev.mnemonic+" "+prev.op_str}
                        for prev in decoded[max(0,i-10):i]
                        if prev.mnemonic.startswith("ldrb")
                    ],
                    "assembly_context":[x.mnemonic+" "+x.op_str for x in context],
                    "reachable_from_host":"UNVERIFIED",
                })
    return {
        "by_value":results,
        "limitation":"Linear chunk disassembly only, no proof these are code rather than data or use USB setup.bRequest; direct compares miss tables and computed dispatch.",
    }


SEMANTIC_ANCHORS = {
    0x60070C4C: ("ldrb", "r3, [r1]"),
    0x60070C50: ("cmp", "r3, #0x30"),
    0x60070C54: ("cmp", "r3, #0x81"),
    0x60070C6C: ("ldrb", "r0, [r1, #1]"),
    0x60070C72: ("ldrb", "r3, [r1, #3]"),
    0x60070CD4: ("ldrb", "r3, [r1, #3]"),
    0x60070CE2: ("strb", "r3, [r4, #8]"),
    0x60070CFC: ("ldrb", "r3, [r1, #5]"),
    0x600F4B40: ("ldrb.w", "r3, [r3, #0x32]"),
    0x600F4B44: ("cmp", "r3, #0x84"),
    0x600F4B4A: ("ldrb.w", "r3, [r3, #0x32]"),
    0x600F4B4E: ("cmp", "r3, #2"),
}

def check_semantic_anchors(decoded):
    for address, expected in SEMANTIC_ANCHORS.items():
        if decoded.get(address)!=expected:
            raise ValueError("Changed original comparison/dataflow anchor: "+hex(address))
    return True

def audit_exact_candidate_anchors(data):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    found={}
    for address in SEMANTIC_ANCHORS:
        offset=address-XIP_BASE
        instruction=next(iter(md.disasm(data[offset:offset+4],address,count=1)),None)
        if instruction:
            found[address]=(instruction.mnemonic,instruction.op_str)
    check_semantic_anchors(found)
    return {
        "candidate_0x81":"compares data buffer byte 0 to 0x81/0x30 and reads bytes +1,+3,+5; then decodes fields into state. No demonstrated linkage to USB setup.bRequest 0x81",
        "candidate_0x84":"compares a field at object +0x32 with 0x84 or 2, with adjacent state predicates; not proven USB setup.bRequest 0x84",
        "anchored_instruction_count":len(SEMANTIC_ANCHORS),
        "USB_setup_source_reached":"NOT VERIFIED",
        "arbitrary_execution_or_update_path":"NOT VERIFIED",
    }


def inspect(data):
    if len(data)!=IMAGE_SIZE or hashlib.sha256(data).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact original signed Bruce SHA-256")
    if data[VENDOR_STRING_OFFSET:VENDOR_STRING_OFFSET+len(VENDOR_STRING)]!=VENDOR_STRING:
        raise ValueError("Changed original vendor component string")
    for xref in VENDOR_REFS:
        if struct.unpack_from("<I",data,xref)[0]!=XIP_BASE+VENDOR_STRING_OFFSET:
            raise ValueError("Changed original vendor component literal reference")
    windows={}
    candidates=[]
    for label,start,end in CANDIDATE_RANGES:
        code=disassemble(data,start,end)
        windows[label]={"file_offsets":[hex(start),hex(end)],
                        "disassembly_preview":code,
                        "potential_host_request_comparisons":[]}
        for i in code:
            val=classify_request_compare(i["mnemonic"],i["operands"])
            if val is not None:
                hit={"pc":i["address"],"value":hex(val),"window":label,
                     "reachability":"NOT VERIFIED; immediate comparison alone"}
                candidates.append(hit)
                windows[label]["potential_host_request_comparisons"].append(hit)
    return {
        "original_sha256_verified":True,
        "source_sha256":IMAGE_SHA256,
        "vendor_component_string":"usb_device_vendor.cc",
        "vendor_component_literal_refs":[hex(XIP_BASE+o) for o in VENDOR_REFS],
        "host_archived_class_requests":["0x81 IN version","0x83 OUT battery init","0x84 IN battery"],
        "windows":windows,
        "candidate_immediate_cmp":candidates,
        "whole_image_cmp_census":census_imm_comparisons(data),
        "focused_candidate_semantics":audit_exact_candidate_anchors(data),
        "receiver_for_host_0x81_0x83_0x84":"NOT IDENTIFIED BY THIS BOUNDED PREVIEW",
        "reachable_arbitrary_execution":"NOT ESTABLISHED",
        "scope":"Static Thumb disassembly of selected XIP windows; functions may cross windows and code may contain literal pools",
        "hardware_io":False,
        "firmware_writes":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--preview",action="store_true")
    args=p.parse_args()
    result=inspect(args.bruce.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    if args.preview:
        for label,details in result["windows"].items():
            print("## "+label+" "+str(details["file_offsets"]))
            for i in details["disassembly_preview"]:
                print(i["address"],i["mnemonic"],i["operands"])
        print("CANDIDATE CMP",json.dumps(result["candidate_immediate_cmp"]))
        print("WHOLE IMAGE CMP CENSUS",json.dumps(result["whole_image_cmp_census"]))
        print("FOCUSED SEMANTICS",json.dumps(result["focused_candidate_semantics"]))
    elif not args.out:
        print(json.dumps(result,indent=2))

if __name__=="__main__":
    main()
