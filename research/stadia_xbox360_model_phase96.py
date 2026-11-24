"""Offline Stadia BLE -> Xbox 360 USB input report model.

Independent Python representation of the published 10-byte Stadia to 20-byte Xbox
report mapping. Source of schema:
https://github.com/danzig666/stadia-dongle-esp/blob/d8392de8f838e12cf16c985b9beb8080c7acd970/main/bridge.c

NO hardware access, network, GPIO, USB, flash, fuse, ROM exploitation or firmware.
NOT a port of the original C code and NOT proof of Windows/console compatibility.
"""
DPAD = (1, 9, 8, 10, 2, 6, 4, 5)


def signed_stick(v: int, reverse: bool = False) -> int:
    value = max(-127, v - 128)
    if reverse:
        value = -value
    return int(32767 * value / 127)


def neutral() -> bytes:
    return bytes((8, 0, 0, 128, 128, 128, 128, 0, 0, 0))


def convert(raw: bytes) -> bytes:
    """Build an Xbox-style twenty-byte *synthetic* report."""
    if len(raw) != 10:
        raise ValueError("Only ten-byte synthetic Stadia BLE reports accepted")
    hat, b1, b2, lx, ly, rx, ry, lt, rt, padding = raw
    out = bytearray(20)
    out[:2] = b"\x00\x14"
    out[2] = DPAD[hat] if hat < 8 else 0
    for source, source_bit, output, output_bit in (
        (b1, 5, 2, 4), (b1, 6, 2, 5), (b2, 0, 2, 6), (b1, 7, 2, 7),
        (b2, 2, 3, 0), (b2, 1, 3, 1), (b1, 4, 3, 2),
        (b2, 6, 3, 4), (b2, 5, 3, 5), (b2, 4, 3, 6), (b2, 3, 3, 7),
    ):
        if source & (1 << source_bit):
            out[output] |= 1 << output_bit
    out[4:6] = bytes((lt, rt))
    for offset, reading, invert in (
        (6, lx, False), (8, ly, True), (10, rx, False), (12, ry, True),
    ):
        out[offset:offset + 2] = signed_stick(reading, invert).to_bytes(
            2, "little", signed=True
        )
    return bytes(out)
