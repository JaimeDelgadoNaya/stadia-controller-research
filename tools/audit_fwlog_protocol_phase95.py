"""Read-only parser for synthetic/recorded Stadia firmware vendor-bulk log messages.

Based on the user-supplied fwlog-kit message schema. Imports no USB/HID modules,
sends no commands, reads no device state and performs no filesystem writes.
Identity strings and unlock tokens are intentionally never returned.
"""
from __future__ import annotations

MAX_MESSAGE_BYTES = 65536
MAX_FIELD_BYTES = 32768
LEVEL_NAMES = {0x14: "debug", 0x1e: "info", 0x28: "error"}


class MalformedMessage(ValueError):
    """Invalid protobuf frame or unsupported wire encoding."""


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise MalformedMessage("truncated varint")
        b = data[pos]
        pos += 1
        if shift == 63 and (b & 0x7e):
            raise MalformedMessage("varint overflow")
        value |= (b & 0x7f) << shift
        if not b & 0x80:
            return value, pos
    raise MalformedMessage("varint too long")


def decode_fields(data: bytes) -> dict[int, bytes | int]:
    """One protobuf message level, with explicit size and boundary guards."""
    if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_BYTES:
        raise MalformedMessage("invalid or oversized message")
    fields: dict[int, bytes | int] = {}
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        number, wire = key >> 3, key & 7
        if not number or number in fields:
            raise MalformedMessage("invalid or duplicate field")
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 2:
            size, pos = _varint(data, pos)
            if size > MAX_FIELD_BYTES or size > len(data) - pos:
                raise MalformedMessage("truncated or oversized length-delimited field")
            value = data[pos:pos + size]
            pos += size
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if pos + size > len(data):
                raise MalformedMessage("truncated fixed-width field")
            value = int.from_bytes(data[pos:pos + size], "little")
            pos += size
        else:
            raise MalformedMessage(f"unsupported wire type {wire}")
        fields[number] = value
    return fields


def _int_field(m: dict[int, bytes | int], number: int, default: int = 0) -> int:
    value = m.get(number, default)
    if not isinstance(value, int):
        raise MalformedMessage(f"field {number} must be an integer")
    return value


def _text_field(m: dict[int, bytes | int], number: int) -> str:
    value = m.get(number, b"")
    if not isinstance(value, bytes):
        raise MalformedMessage(f"field {number} must be bytes")
    return value.decode("utf-8", "replace")


def inspect_frame(data: bytes, include_log_text: bool = False) -> dict[str, object]:
    """Return only a minimal safe summary; content/identities stay redacted by default."""
    outer = decode_fields(data)
    if 6 in outer:
        if not isinstance(outer[6], bytes):
            raise MalformedMessage("firmware log must be a length-delimited submessage")
        log = decode_fields(outer[6])
        level = _int_field(log, 5)
        out: dict[str, object] = {
            "kind": "firmware_log",
            "timestamp": _int_field(log, 1),
            "level": LEVEL_NAMES.get(level, f"unknown:{level}"),
            "source_file": _text_field(log, 3),
            "source_line": _int_field(log, 4),
            "message_redacted": not include_log_text,
        }
        if include_log_text:
            out["message"] = _text_field(log, 2)
        return out
    if 3 in outer:
        if not isinstance(outer[3], bytes):
            raise MalformedMessage("challenge must be a length-delimited submessage")
        ch = decode_fields(outer[3])
        return {
            "kind": "unlock_challenge",
            "state": _int_field(ch, 3),
            "identity_and_token_redacted": True,
        }
    if 2 in outer:
        if not isinstance(outer[2], bytes):
            raise MalformedMessage("status must be a length-delimited submessage")
        status = decode_fields(outer[2])
        return {"kind": "status", "code": _int_field(status, 1)}
    return {"kind": "unknown", "field_numbers": sorted(outer)}


__all__ = ("MalformedMessage", "decode_fields", "inspect_frame")
