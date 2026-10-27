"""Phase 82: read-only, SHA-pinned decode of HAB CSF UNLOCK records.

A HAB CSF UNLOCK command is NOT a boot-policy bypass or USB command.
Do not collect device UID; optional UID bytes are never emitted.
"""
import argparse
import json
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import SAMPLES, audit as audit_phase81

ENGINES = {0x0c: "SRTC", 0x1d: "CAAM", 0x1e: "SNVS", 0x21: "OCOTP"}
FEATURE_FLAGS = {
    "CAAM": {0x1: "MID", 0x2: "RNG", 0x4: "MFG"},
    "OCOTP": {0x1: "FIELD_RETURN", 0x2: "SRK_REVOKE",
              0x4: "SCS", 0x8: "JTAG"},
}
# References: NXP CST Users Guide, HAB Unlock chapter, and NXP SPSDK
# spsdk/image/hab/commands/cmd_unlock.py. Do not infer runtime effects.


def decode_unlock_record(record):
    """Decode one bounded CSF command, refusing to disclose any UID bytes."""
    if len(record) < 8 or record[0] != 0xb2:
        raise ValueError("Not a complete CSF UNLOCK command")
    declared = int.from_bytes(record[1:3], "big")
    if declared != len(record) or declared not in (8, 16):
        raise ValueError("Invalid UNLOCK command length")
    engine = ENGINES.get(record[3], "UNKNOWN_ENGINE")
    features = int.from_bytes(record[4:8], "big")
    known_flags = FEATURE_FLAGS.get(engine, {})
    selected = [name for flag, name in sorted(known_flags.items())
                if features & flag]
    unknown_mask = features & ~sum(known_flags)
    return {
        "engine_code": f"0x{record[3]:02x}",
        "engine": engine,
        "feature_mask": f"0x{features:08x}",
        "features": selected,
        "unmapped_features_mask": f"0x{unknown_mask:08x}",
        "length_bytes": declared,
        "has_uid_field": declared == 16,
        "uid_value": "REDACTED_IF_PRESENT",
        "interpretation_limit": (
            "CSF signed-image metadata, not runtime fuse/engine state, "
            "not removal of HAB signature verification or ROM bypass"
        ),
    }


def audit_unlock(image, sample):
    base = audit_phase81(image, sample)
    csf_offset = SAMPLES[sample]["csf"]
    results = []
    for cmd in base["csf"]["commands"]:
        if cmd["tag"] != "0xb2":
            continue
        offset = csf_offset + int(cmd["relative_offset"], 16)
        size = cmd["length"]
        record = image[offset:offset + size]
        decoded = decode_unlock_record(record)
        decoded["relative_csf_offset"] = cmd["relative_offset"]
        results.append(decoded)
    return {
        "phase": 82,
        "sample": sample,
        "original_sha256": base["sample_sha256"],
        "unlock_commands": results,
        "unlock_count": len(results),
        "hab_configuration": "CLOSED on one physically measured controller; from phase31 evidence",
        "bootrom_hab_version": "UNKNOWN_NOT_MEASURED",
        "no_device_access": True,
        "no_otp_or_flash_modification": True,
        "no_custom_firmware_execution_proven": True,
        "scope": "Static authorized OEM CSF fields; no runtime engine state or parser acceptance claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--sample", choices=sorted(SAMPLES), required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    output = json.dumps(audit_unlock(args.image.read_bytes(), args.sample),
                        indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
