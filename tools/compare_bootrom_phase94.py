#!/usr/bin/env python3
"""Compare two raw internal RT106x BootROM images OFFLINE. No USB or flash operations."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROM_BASE = 0x00200000
ROM_SIZE = 0x20000
EXPECTED_REFERENCE_SHA256 = "a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e"
# Author-assigned symbols/addresses from nxp-sdp-overrun README and main.py.
ROM_ANCHORS = {
    "enable_mpu": 0x0020CAB8,
    "USB_DeviceClassInit": 0x0020D758,
    "USB_DeviceEhciIsrFunction": 0x0020E34C,
    "sdp_hid_callback": 0x0020EA7E,
    "sdp_usb_pump": 0x0020ED38,
    "sdp_usb_run": 0x0020EF7C,
    "HAB_GET_CONFIG_FN": 0x002147F8,
}

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_rom(path: str | Path) -> bytes:
    data = Path(path).read_bytes()
    if len(data) != ROM_SIZE:
        raise ValueError(
            f"{path}: {len(data)} bytes; expected {ROM_SIZE} bytes raw internal "
            "BootROM, NOT external NOR flash or a signed bootloader"
        )
    return data

def compare(reference: bytes | None, candidate: bytes | None,
            expected_reference_sha: str = EXPECTED_REFERENCE_SHA256,
            window_bytes: int = 64) -> dict:
    if window_bytes <= 0 or window_bytes > 256:
        raise ValueError("window_bytes must be between 1 and 256")
    for name, data in (("reference", reference), ("candidate", candidate)):
        if data is not None and len(data) != ROM_SIZE:
            raise ValueError(f"{name} must be exactly {ROM_SIZE} bytes")
    result = {
        "reference": {
            "provided": reference is not None,
            "sha256": digest(reference) if reference is not None else None,
            "matches_documented_sha256": digest(reference) == expected_reference_sha
               if reference is not None else None,
        },
        "candidate": {
            "provided": candidate is not None,
            "sha256": digest(candidate) if candidate is not None else None,
        },
        "rom_base": f"0x{ROM_BASE:08x}",
        "rom_size_bytes": ROM_SIZE,
        "window_bytes_per_anchor": window_bytes,
        "anchor_windows": {},
        "exact_binary_match": None,
        "status": None,
        "stadia_rom_provenance_verified": False,
        "actual_stadia_exploit_execution_verified": False,
        "warning": (
            "Byte/window similarity cannot establish device provenance or exploitability. "
            "No USB, hardware or flash access is performed."
        ),
    }
    if reference is None:
        result["status"] = "REFERENCE_MISSING"
        return result
    if digest(reference) != expected_reference_sha:
        result["status"] = "UNVERIFIED_REFERENCE_HASH"
        return result
    if candidate is None:
        # Hash all seven windows on the verified public ROM reference.
        # No candidate means the match remains UNKNOWN, not TRUE.
        for name, address in ROM_ANCHORS.items():
            start = max(0, (address - ROM_BASE) - window_bytes // 2)
            stop = min(ROM_SIZE, start + window_bytes)
            result["anchor_windows"][name] = {
                "rom_address": f"0x{address:08x}",
                "window_start": f"0x{ROM_BASE+start:08x}",
                "reference_sha256": digest(reference[start:stop]),
                "candidate_sha256": None,
                "match": None,
            }
        result["status"] = "CANDIDATE_MISSING"
        return result
    result["exact_binary_match"] = reference == candidate
    for name, address in ROM_ANCHORS.items():
        start = max(0, (address - ROM_BASE) - window_bytes // 2)
        stop = min(ROM_SIZE, start + window_bytes)
        a, b = reference[start:stop], candidate[start:stop]
        result["anchor_windows"][name] = {
            "rom_address": f"0x{address:08x}",
            "window_start": f"0x{ROM_BASE+start:08x}",
            "reference_sha256": digest(a),
            "candidate_sha256": digest(b),
            "match": a == b,
        }
    if result["exact_binary_match"]:
        result["status"] = "REFERENCE_IDENTICAL_BYTES_PROVENANCE_UNVERIFIED"
    elif all(item["match"] for item in result["anchor_windows"].values()):
        result["status"] = "ONLY_SELECTED_REFERENCE_WINDOWS_MATCH"
    else:
        result["status"] = "REFERENCE_ANCHOR_MISMATCH"
    return result

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference", help="128 KiB raw RT1060 internal BootROM reference")
    p.add_argument("--candidate", help="128 KiB raw internal BootROM candidate")
    p.add_argument("--window-bytes", type=int, default=64)
    p.add_argument("--out", help="optional JSON evidence output")
    args = p.parse_args()
    if args.candidate and not args.reference:
        p.error("--candidate requires --reference")
    result = compare(
        read_rom(args.reference) if args.reference else None,
        read_rom(args.candidate) if args.candidate else None,
        window_bytes=args.window_bytes,
    )
    data = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(data, encoding="utf-8")
    print(data, end="")

if __name__ == "__main__":
    main()
