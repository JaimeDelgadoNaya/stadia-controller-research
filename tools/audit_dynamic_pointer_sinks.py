"""Phase 25 — SHA-locked offline audit of two unresolved pointer sinks.

The tool examines selected instruction regions of one user-extracted Stadia
bootloader A (build 169429). It does not connect to USB or modify hardware.

It reports what the instructions do to *incoming unknown pointers*, not their
runtime addresses. It cannot prove that no other function writes callback
fields, or that host-supplied USB data reaches these functions.
"""
import argparse
import hashlib
import json
from pathlib import Path

try:
    from .audit_interprocedural_aliases import decode_thumb_jump
except ImportError:
    from audit_interprocedural_aliases import decode_thumb_jump

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"

# Entire regions are attested by SHA in addition to whole-image verification.
REGIONS = {
    "transfer_opaque_pointee": (
        0x9048, 0x9174,
        "6c7ce7cefc72ac6df2a368bd994d9730222f75097b008ce40e348eb43dddd769"),
    "list_unlink_opaque_node": (
        0x109FE, 0x10A20,
        "fdc286134a639f4c97aaccb60d18a8c2e408aee918f5d2ff934945342f3be166"),
    "list_caller": (
        0x11DC8, 0x11DF4,
        "9feff6083c2aa76a8068b6da5f9bedca0fee70a73652be8aae600ec42069ffb9"),
}

# Selected instructions; anchored to exact bytes, not guessed symbols.
INSTRUCTIONS = {
    0x9048: ("2de9f047", "push saved registers"),
    0x904C: ("00f1a405", "r5 = input r0 + 0xA4"),
    0x9052: ("0446", "r4 = input r0"),
    0x9074: ("94f85831", "read byte [input+0x158]"),
    0x909C: ("d4f85c31", "read word [input+0x15C]"),
    0x90D8: ("04f16c01", "r1 = input+0x6C"),
    0x9100: ("fbf776f8", "call 0x608041F0"),
    0x9104: ("fff7bafe", "call 0x60808E7C"),
    0x9112: ("04f1f800", "r0 = input+0xF8"),
    0x911A: ("d4f85401", "read word [input+0x154]"),
    0x912E: ("04f16c01", "r1 = input+0x6C"),
    0x9150: ("fbf74ef8", "call 0x608041F0"),
    0x915E: ("04f1f800", "r0 = input+0xF8"),
    0x109FE: ("d0e90112", "r1/r2 = [node+4]/[node+8]"),
    0x10A02: ("0369", "r3 = [node+0x10]"),
    0x10A04: ("8a60", "store next at [previous+8]"),
    0x10A06: ("8268", "r2 = [node+8]"),
    0x10A08: ("5160", "store previous at [next+4]"),
    0x10A0A: ("5968", "read [owner+4]"),
    0x10A10: ("5a60", "conditional owner+4 update"),
    0x10A14: ("0261", "clear [node+0x10]"),
    0x10A18: ("013a", "decrement owner count value"),
    0x10A1A: ("1a60", "store decremented count to owner+0x00"),
    0x10A1C: ("1868", "read owner count value"),
    0x11DCA: ("c368", "load parent from [context+0xC]"),
    0x11DCC: ("dc68", "load link from [parent+0xC]"),
    0x11DDC: ("04f11805", "r5 = dynamic link+0x18"),
    0x11DE2: ("fef70cfe", "call list-unlink with dynamic link+0x18"),
    0x11DEC: ("251d", "r5 = dynamic link+4"),
    0x11DF0: ("fef705fe", "call list-unlink with dynamic link+4"),
}

DIRECT_EDGES = {
    0x9062: 0x101AA,
    0x9080: 0x101BC,
    0x9100: 0x41F0,
    0x9104: 0x8E7C,
    0x9116: 0x1022C,
    0x9120: 0x8E7C,
    0x9150: 0x41F0,
    0x9154: 0x8E7C,
    0x9162: 0x1022C,
    0x11DE2: 0x109FE,
    0x11DF0: 0x109FE,
}

# This list describes verified instruction access types, not proofs that
# unknown pointees do or do not alias USB callback storage.
LIST_WRITES = (
    ("0x60810a04", "previous + 0x08", "next pointer", "unknown pointee"),
    ("0x60810a08", "next + 0x04", "previous pointer", "unknown pointee"),
    ("0x60810a10", "owner + 0x04", "next pointer (conditional)", "unknown pointee"),
    ("0x60810a14", "node + 0x10", "zero", "unknown node"),
    ("0x60810a1a", "owner + 0x00", "decremented count", "unknown pointee"),
)


def fmt(offset):
    return f"0x{BASE+offset:08x}"


def scan(image, expected_sha256=SHA256, ranges=REGIONS):
    """Optional digest overrides are only for synthetic tests, never the CLI."""
    if len(image) != SIZE:
        raise ValueError("Expected exact 131072-byte bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Unexpected SHA-256 for build 169429")
    for name, (start, end, known_digest) in ranges.items():
        if not 0 <= start < end <= SIZE:
            raise ValueError("Invalid attested range")
        if hashlib.sha256(image[start:end]).hexdigest() != known_digest:
            raise ValueError(f"Code-region SHA mismatch: {name}")
    for offset, (encoding, _) in INSTRUCTIONS.items():
        actual = image[offset:offset+len(encoding)//2]
        if actual != bytes.fromhex(encoding):
            raise ValueError(f"Instruction anchor mismatch at {fmt(offset)}")
    edges=[]
    for source, target in DIRECT_EDGES.items():
        kind, decoded = decode_thumb_jump(image, source)
        if (kind, decoded) != ("BL", BASE+target):
            raise ValueError(f"Direct BL edge changed at {fmt(source)}")
        edges.append({"callsite":fmt(source),"target":fmt(target),
                      "kind":"BL", "host_reachable":"NOT ESTABLISHED"})

    return {
        "phase":25,"bootloader_build":169429,"size_bytes":SIZE,
        "sha256_verified":True,"sha256":digest,
        "device_access":False,"usb_transactions":False,
        "flash_or_fuse_writes":False,
        "attested_regions":[{"name":name,"start":fmt(start),"end_exclusive":fmt(end),
                             "sha256":known_digest} for name,(start,end,known_digest) in ranges.items()],
        "instruction_anchors":[{"address":fmt(at),"operation":meaning}
                               for at,(_,meaning) in sorted(INSTRUCTIONS.items())],
        "direct_calls":edges,
        "transfer_routine":{
            "entry":"0x60809048",
            "argument_r0":"opaque pointer loaded from global+0x560/+0x568/+0x570 (depending on caller)",
            "read_offsets_from_incoming_pointer":["0x00","0x154","0x158","0x15c"],
            "argument_derivations":["input+0xa4","input+0x6c","input+0xf8"],
            "direct_stores_through_input":"NONE IN ATTESTED REGION",
            "local_stores":"STACK only; other functions receive derived arguments",
            "not_yet_a_usb_packet_parser":True,
            "unknown":"pointee value, target of delegated effects, host reachability"
        },
        "linked_list_unlink":{
            "entry":"0x608109fe",
            "argument_r0":"opaque node pointer derived from RAM-linked structure",
            "read_offsets":["node+0x04","node+0x08","node+0x10",
                            "owner+0x04","owner+0x00"],
            "writes":[{"at":at,"destination":dst,"value":value,"address_class":address_class}
                      for at,dst,value,address_class in LIST_WRITES],
            "caller_chain":{
                "function":"0x60811dc8",
                "source_context":"global+0x59c in earlier phase, indirectly",
                "pointer_loads":["parent = [context+0xc]","link = [parent+0xc]"],
                "calls_with_pointers":["link+0x18","sometimes link+0x04"],
                "dynamic_objects":"NOT RESOLVED"
            },
            "any_write_address_proven_to_be_usb_callback_field":False,
            "absence_of_runtime_aliasing_proven":False,
        },
        "callback_fields_absolute":["0x20009170","0x20009174","0x20009178","0x2000917c"],
        "conclusions":{
            "static_accesses_to_known_callbacks":"NONE DEMONSTRATED THROUGH THESE OPAQUE INPUTS",
            "pointer_alias_to_callback_fields":"NOT PROVEN OR EXCLUDED",
            "host_usb_to_parser":"NOT DEMONSTRATED",
            "host_to_flash_writer":"NOT DEMONSTRATED",
            "hab_closed_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED"
        },
        "limitations":"Selected authenticated code bytes and direct calls only; no interprocedural pointer-value proof, live RAM observations, or whole-image CFG."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path,help="Private local matching bootloader A")
    p.add_argument("--out",type=Path,help="Optional local JSON path")
    args=p.parse_args()
    text=json.dumps(scan(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(text,encoding="utf-8")
    else:
        print(text,end="")


if __name__=="__main__":
    main()
