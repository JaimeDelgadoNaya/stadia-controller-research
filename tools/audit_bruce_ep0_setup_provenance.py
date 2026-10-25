"""Bruce EP0 SETUP bRequest provenance triage on the exact signed OEM image.

Finds patterns consistent with a USB control SETUP packet, whose first byte is
bmRequestType and second byte is bRequest. Does NOT assume that a byte compare
on 0x81/0x83/0x84 is host-reachable. No USB/device/flash APIs.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE

BASE = ASSUMED_XIP_BASE
# Prior phase found eight loose Thumb-immediate comparisons in linear source
# decoding. Their PC values are candidates, not guaranteed function entrypoints.
CANDIDATES = {
    0x60070C54: 0x81,
    0x600EA274: 0x81,
    0x6006E55C: 0x83,
    0x600AEADC: 0x84,
    0x600AED00: 0x84,
    0x600AEE5C: 0x84,
    0x600F4416: 0x84,
    0x600F4B44: 0x84,
}
USB_SETUP_FIELDS = {
    "bmRequestType": 0,
    "bRequest": 1,
    "wValue": (2, 3),
    "wIndex": (4, 5),
    "wLength": (6, 7),
}
# Direct register references, not a full interprocedural backward slice.
BYTE_LOAD = re.compile(
    r"^(r(?:1[0-2]|[0-9])),\s*\[(r(?:1[0-2]|[0-9]))(?:,\s*#(?:0x([0-9a-f]+)|([0-9]+)))?\]$"
)


def parse_byte_load(mnemonic, operands):
    """Return (destination, base, displacement) for a simple LDRB."""
    if mnemonic.lower().split(".")[0] != "ldrb":
        return None
    m = BYTE_LOAD.match(operands.lower().strip())
    if not m:
        return None
    off = int(m.group(3), 16) if m.group(3) else (int(m.group(4)) if m.group(4) else 0)
    return (m.group(1), m.group(2), off)


def parse_immediate_compare(mnemonic, operands):
    if mnemonic.lower().split(".")[0] != "cmp":
        return None
    m = re.match(r"^(r(?:1[0-2]|[0-9])),\s*#(0x[0-9a-f]+|\d+)$",
                 operands.lower().strip())
    if not m:
        return None
    return (m.group(1), int(m.group(2), 0))


def immediate_provenance(instructions, target_pc, target_value, lookbehind=32):
    """Conservative within-window LDRB-to-CMP relation; no calls/aliases.

    A matching register byte-load is 'local candidate' only; it may be
    overwritten by intervening instructions, or the source object may not be
    a USB setup buffer. The result is evidence for prioritization, not proof.
    """
    matches = [i for i, x in enumerate(instructions) if x["pc"] == target_pc]
    if len(matches) != 1:
        raise ValueError("candidate PC missing or repeated in decode: " + hex(target_pc))
    idx = matches[0]
    cmp_value = parse_immediate_compare(instructions[idx]["m"], instructions[idx]["op"])
    if cmp_value is None or cmp_value[1] != target_value:
        raise ValueError("candidate immediate instruction changed: " + hex(target_pc))
    reg = cmp_value[0]
    prior = []
    for row in reversed(instructions[max(0, idx-lookbehind):idx]):
        loaded = parse_byte_load(row["m"], row["op"])
        if loaded and loaded[0] == reg:
            prior.append({"pc": hex(row["pc"]), "base": loaded[1],
                          "offset": loaded[2]})
            break
    last = prior[0] if prior else None
    return {
        "pc": hex(target_pc),
        "immediate": hex(target_value),
        "compared_register": reg,
        "nearest_same_register_ldrb": last,
        "direct_ldrb_at_setup_brequest_offset_1": bool(last and last["offset"] == 1),
        "direct_ldrb_at_payload_first_byte_offset_0": bool(last and last["offset"] == 0),
        "usb_setup_object_provenance_verified": False,
        "executable_and_reachable_from_ep0_verified": False,
        "warning": "Linear instruction window is not a CFG; nearest load may be from another branch, object, or overwritten register.",
    }


def decode_window(image, candidate, before=100, after=120):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    offset = candidate - BASE
    start = max(0, (offset - before) & ~1)
    stop = min(0xFF000, offset + after)
    dec = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    return [{"pc": i.address, "m": i.mnemonic, "op": i.op_str}
            for i in dec.disasm(image[start:stop], BASE+start)]


def setup_pair_candidates(instructions, *, max_gap=14):
    """Identify local LDRB [base,#0]/[base,#1] pairs and CMP candidates.

    No claim of real USB layout: a shared base register can refer to many
    structures; chunk linear disassembly can include data/pools.
    """
    output=[]
    for idx, row in enumerate(instructions):
        one=parse_byte_load(row["m"],row["op"])
        if one is None or one[2]!=1:
            continue
        recent=instructions[max(0,idx-max_gap):idx]
        zero=next((x for x in reversed(recent)
                   if (lambda a: a and a[1]==one[1] and a[2]==0)(
                       parse_byte_load(x["m"],x["op"]))),None)
        if zero is None:
            continue
        near=instructions[idx:min(len(instructions),idx+max_gap)]
        cmp_pairs=[]
        for x in near:
            parsed=parse_immediate_compare(x["m"],x["op"])
            if parsed is not None:
                cmp_pairs.append((x["pc"],parsed[0],parsed[1]))
        interesting=[{"pc":hex(pc),"register":r,"immediate":hex(v)}
                     for pc,r,v in cmp_pairs if v in (0x21,0xA1,0x81,0x83,0x84)]
        output.append({
            "load_type_zero":hex(zero["pc"]),
            "load_request_one":hex(row["pc"]),
            "base_register":one[1],
            "compares_control_request_values_nearby":interesting,
            "evidence":"same-base local byte-load pattern; may be non-USB or unexecuted",
        })
    return output


def scan_signed_xip_setup_pairs(image, limit=75):
    """Bounded linear XIP pass; deliberately excludes relocated ITCM."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
    start=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    all_pairs=[]
    interesting=[]
    for off in range(start,0xFF000,0x2000):
        inst=[{"pc":v.address,"m":v.mnemonic,"op":v.op_str}
              for v in dec.disasm(image[off:min(off+0x2000,0xFF000)],BASE+off)]
        chunk_pairs=setup_pair_candidates(inst)
        all_pairs.extend(chunk_pairs)
        interesting.extend(x for x in chunk_pairs if x["compares_control_request_values_nearby"])
    return {
        "same_register_ldrb_offset_0_and_1_patterns":len(all_pairs),
        "with_nearby_control_value_compares":len(interesting),
        "nearby_comparison_candidates":interesting[:limit],
        "candidate_list_truncated":len(interesting)>limit,
        "method_limit":"Inexact linear XIP decoding, fixed windows and one-register base matching; misses ITCM, normalized/indirect/table dispatch, and does not establish EP0 provenance.",
        "verified_usb_setup_callback":False,
    }


def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Exact SHA-256-verified original Bruce update image required")
    rows=[]
    for pc,value in CANDIDATES.items():
        window=decode_window(image,pc)
        detail=immediate_provenance(window,pc,value)
        rows.append({**detail,
                     "window": [
                         {"pc":hex(x["pc"]), "mnemonic":x["m"], "operands":x["op"]}
                         for x in window if pc-36 <= x["pc"] <= pc+42
                     ]})
    return {
        "source_sha256_verified":True,
        "source_sha256":IMAGE_SHA256,
        "scope":"Bounded original signed XIP Thumb disassembly; no ITCM dynamic event trace",
        "usb_setup_layout": USB_SETUP_FIELDS,
        "host_class_requests":["0xa1/0x81 IN version",
                               "0x21/0x83 OUT battery init",
                               "0xa1/0x84 IN battery"],
        "original_8_loosely_decoded_candidates":rows,
        "broader_setup_shape_census":scan_signed_xip_setup_pairs(image),
        "direct_setup_brequest_offset_1_byte_load_candidates":sum(
            1 for row in rows if row["direct_ldrb_at_setup_brequest_offset_1"]),
        "established_EP0_registered_callback":None,
        "established_host_brequest_to_receiver":False,
        "established_custom_execution_or_recovery":False,
        "limitations":[
            "No backward pointer origin or class-interface callback registration established",
            "Function boundaries and control-flow reachability are not reconstructed",
            "USB requests may be handled via lookup tables, normalized values or indirect branches",
            "Original signed update image not a readback of installed flash",
        ],
        "controller_connected":False,
        "usb_sent":False,
        "flash_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--compact",action="store_true")
    a=p.parse_args()
    report=audit(a.bruce.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    if a.compact:
        for row in report["original_8_loosely_decoded_candidates"]:
            print(row["pc"],row["immediate"],row["nearest_same_register_ldrb"],
                  "exact_OFFSET_1?",row["direct_ldrb_at_setup_brequest_offset_1"])
        print("BROADER POTENTIAL EP0 SETUP SHAPES",json.dumps(report["broader_setup_shape_census"]))
    elif not a.out:
        print(json.dumps(report,indent=2))

if __name__=="__main__":
    main()
