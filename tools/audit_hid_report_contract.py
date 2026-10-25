"""Decode HID report field sizes offline. Never open or write a USB device."""
import argparse
import json
from pathlib import Path


def decode(descriptor):
    offset = 0
    state = {"usage_page": 0, "size": 0, "count": 0, "report_id": 0,
             "logical_min": 0, "logical_max": 0}
    stack, usages, fields, bit_offsets = [], [], [], {}
    while offset < len(descriptor):
        prefix = descriptor[offset]
        offset += 1
        if prefix == 0xfe:
            raise ValueError("Long HID items are outside this bounded decoder")
        length = (0, 1, 2, 4)[prefix & 3]
        if offset + length > len(descriptor):
            raise ValueError("Truncated HID short item")
        raw = descriptor[offset:offset + length]
        offset += length
        value = int.from_bytes(raw, "little")
        kind, tag = (prefix >> 2) & 3, prefix >> 4
        if kind == 1:
            if tag == 0:
                state["usage_page"] = value
            elif tag == 1:
                state["logical_min"] = int.from_bytes(raw, "little", signed=True)
            elif tag == 2:
                state["logical_max"] = int.from_bytes(raw, "little", signed=state["logical_min"] < 0)
            elif tag in (7, 8, 9):
                state[{7: "size", 8: "report_id", 9: "count"}[tag]] = value
                if tag == 8 and not 1 <= value <= 255:
                    raise ValueError("Invalid HID report ID")
            elif tag == 10:
                stack.append(dict(state))
            elif tag == 11:
                if not stack:
                    raise ValueError("HID global stack underflow")
                state = stack.pop()
        elif kind == 2 and tag == 0:
            usages.append(value)
        elif kind == 0:
            if tag in (8, 9, 11):
                direction = {8: "input", 9: "output", 11: "feature"}[tag]
                key = (direction, state["report_id"])
                start = bit_offsets.get(key, 0)
                bits = state["size"] * state["count"]
                fields.append({**state, "direction": direction,
                               "usages": list(usages), "flags": value,
                               "payload_bit_offset": start, "bits": bits})
                bit_offsets[key] = start + bits
            # Every main item consumes local state, including Collection.
            usages = []
    if stack:
        raise ValueError("Unbalanced HID global stack")
    reports = [{"direction": key[0], "report_id": key[1], "payload_bits": bits,
                "wire_bytes": (bits + 7) // 8 + bool(key[1])}
               for key, bits in sorted(bit_offsets.items())]
    return {"reports": reports, "fields": fields,
            "scope": "Short-item report sizes and explicit usages only; usage ranges and collection semantics not interpreted"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path,
                        help="JSON with descriptor_hex from an owner-device descriptor read")
    args = parser.parse_args()
    source = json.loads(args.evidence.read_text(encoding="utf-8"))
    print(json.dumps(decode(bytes.fromhex(source["descriptor_hex"])), indent=2))


if __name__ == "__main__":
    main()
