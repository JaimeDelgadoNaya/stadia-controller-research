#!/usr/bin/env python3
"""Prepare a *hypothetical*, unsigned RT1060-style SDP RAM image OFFLINE.

This packages the exact 20-byte inert proof-marker demo (phase 97) behind
documented i.MX RT IVT/Boot Data structure with IVT at +0x400. It never
contacts USB/SDP or real hardware; HAB CLOSED would ordinarily reject an
unsigned image, and the example has NOT been validated by the target ROM.

Reference: NXP MCUXpresso Manufacturing User Guide (IVT + Boot Data).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

LOAD_BASE = 0x20000000
IMAGE_SIZE = 0x2000
IVT_OFFSET = 0x400
BOOT_DATA_OFFSET = 0x420
IVT_HEADER = 0x412000D1
DEMO_SHA256 = "68a75935017e47c373d2df0b9294c31781705894511bc62fea78b6a265806f38"
DEMO_BYTES = 20

def build_demo_image(demo: bytes) -> bytes:
    if len(demo) != DEMO_BYTES or hashlib.sha256(demo).hexdigest() != DEMO_SHA256:
        raise ValueError("Only the exact phase97 20-byte harmless RAM marker demo is allowed")
    sp, entry = struct.unpack_from("<II", demo)
    if sp != 0x20010000 or entry != LOAD_BASE + 9:
        raise ValueError("Demo reset vectors differ from verified phase97 fixture")
    image = bytearray(IMAGE_SIZE)
    image[:DEMO_BYTES] = demo
    struct.pack_into("<8I", image, IVT_OFFSET,
                     IVT_HEADER, entry, 0, 0, LOAD_BASE + BOOT_DATA_OFFSET,
                     LOAD_BASE + IVT_OFFSET, 0, 0)
    struct.pack_into("<3I", image, BOOT_DATA_OFFSET, LOAD_BASE, IMAGE_SIZE, 0)
    inspect_demo_image(bytes(image))
    return bytes(image)

def inspect_demo_image(image: bytes) -> dict:
    if len(image) != IMAGE_SIZE:
        raise ValueError("Unexpected i.MX RT hypothetical image size")
    ivt = struct.unpack_from("<8I", image, IVT_OFFSET)
    boot = struct.unpack_from("<3I", image, BOOT_DATA_OFFSET)
    if ivt != (IVT_HEADER, LOAD_BASE + 9, 0, 0,
               LOAD_BASE + BOOT_DATA_OFFSET, LOAD_BASE + IVT_OFFSET, 0, 0):
        raise ValueError("IVT differs from defined, unsigned, RAM-only example")
    if boot != (LOAD_BASE, IMAGE_SIZE, 0):
        raise ValueError("Boot Data differs from defined RAM-only image")
    if hashlib.sha256(image[:DEMO_BYTES]).hexdigest() != DEMO_SHA256:
        raise ValueError("Embedded marker demo changed")
    if any(image[DEMO_BYTES:IVT_OFFSET]) or any(image[BOOT_DATA_OFFSET+12:]):
        raise ValueError("Unexpected nonzero payload beyond the inert example")
    return {
        "source": "NXP IVT/Boot Data structure; example only",
        "load_address": hex(LOAD_BASE),
        "ivt_address": hex(LOAD_BASE + IVT_OFFSET),
        "ivt_header": hex(ivt[0]),
        "entry_thumb_address": hex(ivt[1]),
        "boot_data_address": hex(ivt[4]),
        "boot_data_start": hex(boot[0]),
        "boot_data_size": boot[1],
        "plugin": boot[2],
        "dcd_pointer_is_null": ivt[3] == 0,
        "csf_pointer_is_null": ivt[6] == 0,
        "sha256": hashlib.sha256(image).hexdigest(),
        "structure_valid_by_local_parser_only": True,
        "bootrom_acceptance_proven": False,
        "stadia_compatibility_proven": False,
        "physical_transfer_attempted": False,
        "habsignature_bypass_proven": False,
    }

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase97_marker_bin", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--report", type=Path)
    args = p.parse_args()
    image = build_demo_image(args.phase97_marker_bin.read_bytes())
    report = json.dumps(inspect_demo_image(image), indent=2) + "\n"
    if args.out:
        args.out.write_bytes(image)
    if args.report:
        args.report.write_text(report, encoding="utf-8")
    print(report)

if __name__ == "__main__":
    main()
