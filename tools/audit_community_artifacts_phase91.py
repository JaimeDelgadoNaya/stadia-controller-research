"""Phase 91: offline, read-only intake of privately provided Stadia artifacts.

Never communicates with a device. The bonding store is recognized only; its
contents and fingerprint are intentionally omitted from all output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MAX_BYTES = 32 * 1024 * 1024
IVT_TAG = 0xD1


def _read_limited(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("File missing or exceeds offline size limit")
    return path.read_bytes()


def usb_config_candidates(data):
    """Find descriptor chains by structure, without assuming live USB exposure."""
    matches = []
    for offset in range(0, len(data) - 8):
        if data[offset:offset+2] != b"\x09\x02":
            continue
        total = int.from_bytes(data[offset+2:offset+4], "little")
        if total < 9 or total > 1024 or offset + total > len(data):
            continue
        ifaces, eps, cdc_union, acm, iad = [], [], [], False, False
        pos, end = offset, offset + total
        while pos < end:
            if pos + 2 > end:
                break
            length, kind = data[pos], data[pos+1]
            if length < 2 or pos + length > end:
                break
            item = data[pos:pos+length]
            if kind == 4 and length >= 9:
                ifaces.append({"number": item[2], "class": item[5], "subclass": item[6]})
            elif kind == 5 and length >= 7:
                eps.append(item[2])
            elif kind == 11 and length >= 8:
                iad = True
            elif kind == 0x24 and length >= 4 and item[2] == 2:
                acm = True
            elif kind == 0x24 and length >= 5 and item[2] == 6:
                cdc_union.append([item[3], item[4]])
            pos += length
        if pos != end or not ifaces or len(ifaces) > 8:
            continue
        if len({x["number"] for x in ifaces}) != data[offset+4]:
            continue
        matches.append({
            "file_offset": f"0x{offset:x}",
            "reported_total_length": total,
            "reported_interfaces": data[offset+4],
            "interfaces": ifaces,
            "endpoint_addresses": [f"0x{x:02x}" for x in eps],
            "cdc_acm_functional_descriptor_present": acm,
            "cdc_union_pairs": cdc_union,
            "iad_present": iad,
            "structurally_consistent_in_file": True,
            "actually_exposed_by_usb_device": False,
        })
    return matches


def bootloader_summary(data):
    if not isinstance(data, bytes) or len(data) < 32:
        raise ValueError("Bootloader candidate must be at least 32 bytes")
    if data[0] != IVT_TAG or data[1:3] != b"\x00\x20":
        raise ValueError("No expected NXP IVT at offset zero; do not infer image layout")
    words = struct.unpack_from("<8I", data)
    markers = {
        "cdc_acm_source_string": b"usb_device_cdc_acm.c" in data,
        "vendor_usb_source_string": b"usb_device_vendor.cc" in data,
        "preinstall_auth_error_string": b"New bootloader failed pre-install image authentication." in data,
    }
    return {
        "kind": "ivt_candidate_not_authenticated",
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ivt_offset": 0,
        "ivt_version_byte": data[3],
        "ivt_fields": dict(zip(
            ("entry", "reserved1", "dcd", "boot_data", "self", "csf", "reserved2"),
            (f"0x{word:08x}" for word in words[1:]),
        )),
        "static_string_markers": markers,
        "usb_config_descriptor_candidates": usb_config_candidates(data),
        "oem_signature_validated": False,
        "cdc_descriptor_correctness_validated": False,
        "hardware_compatibility_validated": False,
        "firmware_executed": False,
    }


def bonding_summary(data):
    if not isinstance(data, bytes) or not data.startswith(b"#BONDING"):
        raise ValueError("Not a recognized bonding-store prefix; refuse to inspect")
    return {
        "kind": "private_bonding_store_not_firmware",
        "size_bytes": len(data),
        "content_exported": False,
        "sha256_exported": False,
        "device_identifiers_exported": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootloader", type=Path, help="local candidate image; read only")
    parser.add_argument("--bonding", type=Path, help="private bonding blob; read only")
    args = parser.parse_args(argv)
    if not args.bootloader and not args.bonding:
        parser.error("provide at least one local input")
    report = {"evidence_type": "offline_private_file_intake", "device_actions": False}
    if args.bootloader:
        report["bootloader"] = bootloader_summary(_read_limited(args.bootloader))
    if args.bonding:
        report["bonding"] = bonding_summary(_read_limited(args.bonding))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
