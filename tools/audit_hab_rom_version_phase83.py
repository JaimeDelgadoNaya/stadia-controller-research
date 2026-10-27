"""Phase 83: distinguish signed-image header versions from live HAB BootROM version.

Offline-only, SHA-256-pinned input. Optional *operator-supplied* ROM RVT
snapshot is parsed but NEVER claimed to be an authenticated hardware read.
Neither a pointer slot nor an IVT/CSF version byte is an exact HAB patch version.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import SAMPLES, audit as audit_phase81

RVT_BASE = 0x00200300
HAB_GET_VERSION_SLOT_OFFSET = 0x30
HAB_AUTH_NO_DCD_SLOT_OFFSET = 0x2c
RVT_TAG = 0xdd
ROM_LOWER = 0x00200000
ROM_UPPER_EXCLUSIVE = 0x00220000
MAX_SNAPSHOT = 256


def parse_rvt_snapshot(snapshot):
    """Parse an explicit ROM table snapshot, never perform device/ROM access."""
    if not isinstance(snapshot, bytes) or not 4 <= len(snapshot) <= MAX_SNAPSHOT:
        raise ValueError("Invalid ROM RVT snapshot size")
    if snapshot[0] != RVT_TAG:
        raise ValueError("Expected HAB ROM vector table tag 0xdd")
    length = int.from_bytes(snapshot[1:3], "big")
    if not 4 <= length <= len(snapshot):
        raise ValueError("Invalid or truncated HAB RVT header length")
    if length % 4:
        raise ValueError("HAB RVT length is not word aligned")
    version = snapshot[3]
    if version >> 4 != 4:
        raise ValueError("Unexpected HAB RVT header major version")
    result = {
        "declared_bytes": length,
        "rvt_header_version_byte": f"0x{version:02x}",
        "rvt_header_minor_nibble": version & 15,
        "rvt_header_patch_version": "NOT_ENCODED_IN_HEADER",
        "slot_get_version_address": f"0x{RVT_BASE + HAB_GET_VERSION_SLOT_OFFSET:08x}",
        "slot_authenticate_image_no_dcd_address":
            f"0x{RVT_BASE + HAB_AUTH_NO_DCD_SLOT_OFFSET:08x}",
        "get_version_slot": "NOT_PRESENT_IN_DECLARED_RVT",
    }
    if length >= HAB_AUTH_NO_DCD_SLOT_OFFSET + 4:
        ptr = struct.unpack_from("<I", snapshot, HAB_AUTH_NO_DCD_SLOT_OFFSET)[0]
        result["authenticate_image_no_dcd_slot"] = {
            "pointer": f"0x{ptr:08x}",
            "points_into_documented_rom_region": bool(ptr & 1)
            and ROM_LOWER <= (ptr & ~1) < ROM_UPPER_EXCLUSIVE,
        }
    if length >= HAB_GET_VERSION_SLOT_OFFSET + 4:
        ptr = struct.unpack_from("<I", snapshot, HAB_GET_VERSION_SLOT_OFFSET)[0]
        result["get_version_slot"] = {
            "pointer": f"0x{ptr:08x}",
            "points_into_documented_rom_region": bool(ptr & 1)
            and ROM_LOWER <= (ptr & ~1) < ROM_UPPER_EXCLUSIVE,
            "function_invoked": False,
            "library_patch_version": "UNKNOWN_UNTIL_GET_VERSION_RESULT",
        }
    return result


def audit(image, sample, snapshot=None, get_version_return=None):
    """Audit only signed Google headers, optionally parse unsourced RVT metadata."""
    original = audit_phase81(image, sample)
    spec = SAMPLES[sample]
    ivt_byte = image[spec["ivt"] + 3]
    csf_byte = image[spec["csf"] + 3]
    if ivt_byte >> 4 != 4 or csf_byte >> 4 != 4:
        raise ValueError("Unexpected signed OEM image HAB header major")
    if get_version_return is not None:
        if snapshot is None:
            raise ValueError("A supplied get_version result requires a ROM table snapshot")
        if not 0 <= get_version_return <= 0xffffffff:
            raise ValueError("get_version result outside unsigned 32-bit range")
    rvt = parse_rvt_snapshot(snapshot) if snapshot is not None else None
    return {
        "phase": 83,
        "sample": sample,
        "image_sha256": original["sample_sha256"],
        "signed_file_versions": {
            "ivt_header_version_byte": f"0x{ivt_byte:02x}",
            "csf_header_version_byte": f"0x{csf_byte:02x}",
            "these_bytes_are_exact_rom_hab_version": False,
        },
        "documented_rom_rvt": {
            "base": f"0x{RVT_BASE:08x}",
            "authenticate_image_no_dcd_pointer_slot":
                f"0x{RVT_BASE + HAB_AUTH_NO_DCD_SLOT_OFFSET:08x}",
            "get_version_pointer_slot":
                f"0x{RVT_BASE + HAB_GET_VERSION_SLOT_OFFSET:08x}",
        },
        "operator_supplied_rvt_snapshot": rvt,
        "operator_supplied_get_version_return_raw":
            f"0x{get_version_return:08x}" if get_version_return is not None else None,
        "operator_supplied_data_is_verified_from_owner_hardware": False,
        "actual_owner_bootrom_hab_version": "UNKNOWN_NOT_MEASURED",
        "hab_advisory_applicability": "UNRESOLVED_REQUIRES_ROM_VERSION_AND_REACHABILITY",
        "limits": [
            "OEM IVT/CSF version fields encode data-structure format, not the exact ROM HAB patch level.",
            "RVT slot address is a pointer location and must not be executed as a function.",
            "A supplied RVT snapshot or get_version return is unverified operator metadata unless independently grounded.",
            "NXP documents HAB 4.2.7 exception for get_version and authenticate_image_no_dcd support.",
            "No live ROM code, version result, altered CSF acceptance, custom code execution or HAB bypass proven.",
            "No hardware, SDP, RAM, flash or OTP operations.",
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path, help="Locally held, hash-pinned original OEM binary")
    ap.add_argument("--sample", required=True, choices=sorted(SAMPLES))
    ap.add_argument("--rvt-snapshot", type=Path, help="Optional previously acquired 4..256 byte ROM table snapshot")
    ap.add_argument("--get-version-return", type=lambda x: int(x, 0),
                    help="Optional operator-supplied uint32 response, not independently verified")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    result = audit(args.image.read_bytes(), args.sample,
                   snapshot=args.rvt_snapshot.read_bytes() if args.rvt_snapshot else None,
                   get_version_return=args.get_version_return)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
