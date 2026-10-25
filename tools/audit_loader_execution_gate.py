"""Offline, SHA-locked audit of the original RAM loader's Execute/Call gate."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SHA256 = "c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5"
SIZE = 100672
BASE = 0x20000000
TABLE = 0x15978
# Selected instruction bytes only. No execution, USB, or proprietary image output.
ANCHORS = {
    0x247e: "0d490d4a0e4b9a42bebf51f8040b42f8040bf8e7",
    0x2ef4: "0278531e142b15d80c236ff00b0613fb0266bb6833441e7a002e08bf00232b6353b11b6843b1984723690122db681a60002008e00023f2e742f210701146fff7a5ff42f21070",
    0xa87c: "034b1b68034b1868c0f34000704700bf40441f4060441f40",
    0x9af0: "00f0c4fe00300d4918bf0120f3e7",
    0x39a8: "012810b504d016d3022811d0002010bd06200b4b013a03ebc0000a441c68a14202d35c68a24209d908338342f6d1ede70420044beee70520034bebe7012010bd3c8220206c82202014822020",
    0x3b7c: "f7b5054616461f460c46002945d00a4601460220fff70aff20b1c7f3032323b1012b20d042f2d8701be0",
    0x3244: "d8f800303046009a9d684b46a8470546",
    0x31ec: "d8f81030a2455146db6828bf214693f820200191",
    0x4f5e: "95f8232095f8223043ea0223ea69043a9a420bd30a4a00203a603360bde8f081",
}
WORDS = {0x24b4: 0x200164d8, 0x24b8: 0x20208000,
         0x24bc: 0x20208830, 0x166dc: 0x202081e4,
         0x166c4: 0x20015978, 0x2f64: 0x202081f4,
         0x99d8: 0x0305d886, 0x166cc: 0x20015e8c,
         0x15e94: 0x20003b7d, 0x15f3c: 0x20004ef5,
         0x16124: 0x20015f38}
WRITE_RANGES = [(0x2000, 0x21ff), (0x60000000, 0x60000fff),
                (0x60001000, 0x60001fff), (0x60004000, 0x60ffffff)]
NAMES = {2: "FlashEraseRegion", 3: "ReadMemory", 4: "WriteMemory",
         5: "FillMemory", 7: "GetProperty", 8: "ReceiveSBFile",
         9: "Execute", 10: "Call", 11: "Reset", 17: "ConfigureMemory"}


def command_entry(data, tag):
    if not 1 <= tag <= 21:
        return None
    handler, data_handler, enabled = struct.unpack_from("<3I", data, TABLE + 12 * (tag - 1))
    return {"tag": tag, "name": NAMES.get(tag, "other"),
            "handler": hex(handler), "data_handler": hex(data_handler),
            "enabled_byte": enabled & 255,
            "dispatches": bool((enabled & 255) and handler)}


def ordinary_write_allowed(address, length):
    """Policy model for positive, nonwrapping ranges only, not an exploit model."""
    if length <= 0 or address < 0 or address + length > 0x100000000:
        raise ValueError("only positive nonwrapping 32-bit ranges modeled")
    return any(address >= first and address + length - 1 <= last
               for first, last in WRITE_RANGES)


def usb_fragment_length(remaining, received):
    """Conservative receiver bound, not a promise that 65535-byte HID reports work."""
    if not 0 <= remaining <= 0xffffffff or not 0 <= received <= 0xffff:
        raise ValueError("remaining must be uint32 and received length uint16")
    return min(remaining, received)


def audit(data, expected_sha=SHA256):
    if len(data) != SIZE:
        raise ValueError("loader size mismatch")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha:
        raise ValueError("loader SHA-256 mismatch")
    for offset, encoded in ANCHORS.items():
        needle = bytes.fromhex(encoded)
        if data[offset:offset + len(needle)] != needle:
            raise ValueError("instruction anchor mismatch at " + hex(BASE + offset))
    for offset, value in WORDS.items():
        if struct.unpack_from("<I", data, offset)[0] != value:
            raise ValueError("pointer/literal mismatch at " + hex(BASE + offset))
    entries = [command_entry(data, tag) for tag in NAMES]
    for tag, handler in [(9, 0x200033a1), (10, 0x2000340d)]:
        entry = command_entry(data, tag)
        if entry["enabled_byte"] != 0 or entry["handler"] != hex(handler):
            raise ValueError("Execute/Call table gate changed")
    ranges = [struct.unpack_from("<2I", data, 0x16744 + 8 * n) for n in range(4)]
    if ranges != WRITE_RANGES:
        raise ValueError("write policy ranges changed")
    return {"loader_sha256": digest, "loader_bytes": len(data),
            "method": "Offline instruction and table verification; no device I/O or emulation",
            "startup_copy": {"source": "0x200164d8", "destination": "0x20208000", "bytes": 2096},
            "command_table": "0x20015978", "entry_bytes": 12,
            "dispatcher": "0x20002eb4", "gate_load": "0x20002f0a",
            "disabled_response_status": "0x2710", "commands": entries,
            "get_property_0x11": {"case": "0x20009af0", "callee": "0x2000a87c",
                "source_register": "OCOTP_CFG5 0x401f4460", "bit": 1,
                "meaning": "Fuse-derived status; distinct from the command-table enabled byte"},
            "write_policy": {"data_phase_call": "0x20003250", "backend": "0x20003b7c",
                "policy": "0x200039a8", "operation": 2,
                "initialized_ranges_at": "0x2020826c", "image_offset": "0x16744",
                "ranges_inclusive": [[hex(a), hex(b)] for a, b in ranges],
                "rejected_status": "0x27d8",
                "ordinary_table_patch": "Positive nonwrapping writes to 0x200159e0 or 0x200159ec fail the write policy before generic RAM dispatch.",
                "usb_fragment_gate": {"length_decode": "0x20004f5e..0x20004f78",
                    "width_bits": 16, "conservative_max_bytes": 65535,
                    "remaining_clamp": "0x200031ec..0x200031fe",
                    "backend_length": "min(remaining command bytes, received fragment length)",
                    "result": "A huge declared command length cannot wrap the table-address policy check: backend fragments are at most uint16 on this intact USB path."},
                "scope": "The uint16 bound is conservative, not a demonstrated maximum-size USB transfer. Other mutation paths, malformed/corrupted transport state and general integer-wrap effects remain outside scope."},
            "conclusion": "Execute and Call handlers exist but their table entries are disabled; the normal command dispatcher returns 0x2710 before calling either handler.",
            "limits": ["Applies to this exact original signed loader and its initialized normal dispatch path.",
                "USB WriteMemory fragment sizing and its policy were traced; ReadMemory, other transports and corrupted-state paths were not exhaustively audited.",
                "Does not rule out a separate vulnerability, corrupted dispatch state, other loader image or other execution channel.",
                "No custom execution, signature bypass, flash programming, recovery test or console support was demonstrated."]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    result = audit(args.loader.read_bytes())
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
