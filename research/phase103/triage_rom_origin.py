#!/usr/bin/env python3
"""Phase 103: fail-closed provenance triage for candidate Stadia *internal* BootROM.

This is an OFFLINE classification filter, not a silicon identification oracle.
Matching bytes, size, registers or a self-authored manifest cannot authenticate
the physical origin of a ROM dump. NO hardware, network or exploit functions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

SIZE = 131072
ROM_BASE = 0x00200000
PUBLIC_RT1060_SHA = "a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e"
OWNER_EXTERNAL_BOOTLOADER_A_SHA = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
OWNER_EXTERNAL_BOOTLOADER_B_SHA = "b5a41c3758763bbec72769fab4a2533bf2db0b6312d93d25a695f9e4b9e02260"
KNOWN_EXTERNAL_FLASH_SHA = {
    OWNER_EXTERNAL_BOOTLOADER_A_SHA: "owner_external_bootloader_A_0x60800000",
    OWNER_EXTERNAL_BOOTLOADER_B_SHA: "owner_erased_external_bootloader_B_0x60820000",
}
IVT_MAGIC = b"\xd1\x00\x20\x41"
EXTERNAL_FCB = b"FCFB"
SOURCE_KINDS = {"unknown", "public_rt1060_reference", "external_nor_flash",
                "external_bootloader_partition", "declared_internal_mask_rom"}
ANCHORS = {
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


def classify(data: bytes | None, *,
             reference: bytes | None = None,
             manifest: dict | None = None) -> dict:
    if reference is not None and (len(reference) != SIZE or digest(reference) != PUBLIC_RT1060_SHA):
        raise ValueError("Reference ROM must match the exact public RT1060 SHA-256")
    info = manifest or {}
    if not isinstance(info, dict):
        raise ValueError("Provenance declaration must be a JSON object")
    kind = info.get("source_kind", "unknown")
    if kind not in SOURCE_KINDS:
        raise ValueError("Unknown source_kind in provenance declaration")

    result = {
        "phase": 103, "candidate_provided": data is not None,
        "candidate_size": None if data is None else len(data),
        "candidate_sha256": None if data is None else digest(data),
        "declared_source_kind": kind,
        "declared_acquisition_record": info.get("acquisition_record"),
        "declared_device_observation": info.get("device_observation"),
        "known_reference_sha256": PUBLIC_RT1060_SHA,
        "reference_available_and_verified": reference is not None,
        "matching_reference_windows": None,
        "full_reference_byte_match": None,
        "physical_origin_authenticated": False,
        "stadia_internal_rom_identified": False,
        "actual_stadia_exploit_tested": False,
        "status": None,
        "reason": None,
        "safe_for_automatic_exploit_claim": False,
    }
    def verdict(status: str, reason: str) -> dict:
        result["status"], result["reason"] = status, reason
        return result

    if data is None:
        return verdict("CANDIDATE_MISSING", "No internal-mask-ROM bytes acquired from the device")
    if len(data) != SIZE:
        return verdict("REJECT_WRONG_SIZE", "Not a complete 128 KiB candidate image")

    sha = digest(data)
    if sha in KNOWN_EXTERNAL_FLASH_SHA:
        return verdict("REJECT_KNOWN_EXTERNAL_FLASH", KNOWN_EXTERNAL_FLASH_SHA[sha])
    if data == b"\xff" * SIZE:
        return verdict("REJECT_ERASED_EXTERNAL_OR_BLANK", "All 0xFF bytes are not evidence of mask ROM")
    if data == b"\x00" * SIZE:
        return verdict("REJECT_BLANK", "All zeros are not meaningful internal BootROM evidence")
    if data[:4] == EXTERNAL_FCB or data[0x1000:0x1004] == EXTERNAL_FCB:
        return verdict("REJECT_FLEXSPI_NOR_HEADER",
                       "FCFB denotes an external FlexSPI boot configuration, not a mask-ROM signature")
    if kind in {"external_nor_flash", "external_bootloader_partition"}:
        return verdict("REJECT_DECLARED_EXTERNAL_SOURCE", "Declared external source cannot prove internal ROM")
    if data[:4] == IVT_MAGIC or data[0x1000:0x1004] == IVT_MAGIC:
        return verdict("SUSPECT_BOOT_IMAGE_IVT",
                       "Boot image IVT signature is not a mask-ROM identity marker")

    if reference is not None:
        windows = {}
        for label, addr in ANCHORS.items():
            offset = addr - ROM_BASE - 32
            windows[label] = digest(data[offset:offset + 64]) == digest(reference[offset:offset + 64])
        result["matching_reference_windows"] = windows
        result["full_reference_byte_match"] = data == reference

    if sha == PUBLIC_RT1060_SHA:
        return verdict("PUBLIC_RT1060_BYTES_NOT_DEVICE_PROVENANCE",
                       "Byte identity with a public reference cannot prove that it was read from this Stadia")

    if kind == "declared_internal_mask_rom":
        return verdict("UNVERIFIED_INTERNAL_ROM_DECLARATION",
                       "An operator-supplied manifest alone cannot authenticate silicon or ROM version")
    if result["matching_reference_windows"] and all(result["matching_reference_windows"].values()):
        return verdict("ONLY_REFERENCE_WINDOWS_MATCH",
                       "7 matching windows do not prove provenance, whole-ROM equality or runtime exploitation")
    return verdict("UNKNOWN_128K_IMAGE_NO_PROVENANCE",
                   "Size and unknown hash alone cannot identify internal mask ROM")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path)
    p.add_argument("--reference", type=Path)
    p.add_argument("--manifest", type=Path, help="self-declared acquisition notes, NEVER attestation")
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    manifest = json.loads(a.manifest.read_text()) if a.manifest else None
    result = classify(a.candidate.read_bytes() if a.candidate else None,
                      reference=a.reference.read_bytes() if a.reference else None,
                      manifest=manifest)
    payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        a.out.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
