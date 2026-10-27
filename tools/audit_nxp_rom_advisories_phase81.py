"""Read-only IVT/CSF audit for exact signed Stadia OEM samples.

Does not emulate ROM HAB, access the controller, modify flash, or verify
the hardware-fused SRK. Results are bounded to original SHA-pinned files.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SAMPLES = {
    "bootloader_a": {
        "size": 131072,
        "sha256": "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0",
        "ivt": 0, "csf": 0x18000, "csf_length": 0x60,
        "ivt_self": 0x60001000, "csf_pointer": 0x60818000,
    },
    "bruce_prod": {
        "size": 1050984,
        "sha256": "466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3",
        "ivt": 0xff000, "csf": 0xff030, "csf_length": 0x48,
        "ivt_self": 0x6013f000, "csf_pointer": 0x6013f030,
    },
    "restricted_ram_loader": {
        "size": 100672,
        "sha256": "c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5",
        "ivt": 0x400, "csf": 0x17000, "csf_length": 0x50,
        "ivt_self": 0x20000400, "csf_pointer": 0x20017000,
    },
}
COMMAND_NAMES = {
    0xb1: "SET", 0xbe: "INSTALL_KEY", 0xca: "AUTHENTICATE_DATA",
    0xcc: "WRITE_DATA", 0xcf: "CHECK_DATA", 0xc0: "NOP",
    0xb4: "INITIALIZE", 0xb2: "UNLOCK",
}


def parse_csf(image, at):
    """Walk only the length-delimited CSF commands; never scan arbitrary bytes."""
    if at < 0 or at + 4 > len(image) or image[at] != 0xd4:
        raise ValueError("Missing or invalid CSF header")
    length = int.from_bytes(image[at + 1:at + 3], "big")
    if length < 4 or at + length > len(image):
        raise ValueError("Invalid CSF length")
    cursor = at + 4
    commands = []
    while cursor < at + length:
        if cursor + 4 > at + length:
            raise ValueError("Truncated CSF command header")
        tag = image[cursor]
        size = int.from_bytes(image[cursor + 1:cursor + 3], "big")
        parameter = image[cursor + 3]
        if size < 4 or cursor + size > at + length:
            raise ValueError("Malformed or overlong CSF command")
        deprecated = ({0xcc: "WRITE_DATA", 0xcf: "CHECK_DATA"}.get(tag)
                      or ("SET_MID" if tag == 0xb1 and parameter == 0x01 else None))
        commands.append({
            "relative_offset": hex(cursor - at), "tag": hex(tag),
            "name": COMMAND_NAMES.get(tag, "UNKNOWN"),
            "length": size, "parameter": hex(parameter),
            "deprecated": deprecated,
        })
        cursor += size
    return length, commands


def audit(image, sample):
    if sample not in SAMPLES:
        raise ValueError("Unknown pinned sample")
    spec = SAMPLES[sample]
    if len(image) != spec["size"] or hashlib.sha256(image).hexdigest() != spec["sha256"]:
        raise ValueError("Image length / SHA-256 does not match pinned OEM sample")
    at = spec["ivt"]
    if at + 32 > len(image):
        raise ValueError("IVT outside image")
    ivt = struct.unpack_from("<8I", image, at)
    if ivt[0] != 0x412000d1 or ivt[2] or ivt[7]:
        raise ValueError("Unexpected IVT header or reserved fields")
    if ivt[5] != spec["ivt_self"] or ivt[6] != spec["csf_pointer"]:
        raise ValueError("IVT self/CSF pointer differs from original mapped layout")
    size, commands = parse_csf(image, spec["csf"])
    if size != spec["csf_length"]:
        raise ValueError("CSF length differs from pinned original")
    return {
        "phase": 81,
        "sample": sample,
        "sample_sha256": spec["sha256"],
        "ivt": {
            "offset": hex(at), "self_pointer": hex(ivt[5]),
            "dcd_pointer": hex(ivt[3]), "dcd_is_null": ivt[3] == 0,
            "csf_pointer": hex(ivt[6]),
        },
        "csf": {
            "offset": hex(spec["csf"]), "length": size,
            "commands": commands,
            "deprecated_count": sum(bool(x["deprecated"]) for x in commands),
            "unknown_count": sum(x["name"] == "UNKNOWN" for x in commands),
        },
        "limits": {
            "bootrom_hab_version": "UNKNOWN_NOT_MEASURED",
            "rom_csf_parser_acceptance": "UNKNOWN_NOT_TESTED",
            "fused_srk_trust": "NOT_VERIFIED",
            "modified_image_execution": "NOT_DEMONSTRATED",
            "cve_2022_45163": "ROM SDP confidentiality advisory; not evaluated by IVT/CSF parser",
        },
        "operations": "Offline read-only original-image audit; no device access",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--sample", required=True, choices=sorted(SAMPLES))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = audit(args.image.read_bytes(), args.sample)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
