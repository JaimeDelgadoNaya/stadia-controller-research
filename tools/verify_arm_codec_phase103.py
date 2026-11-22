"""Read-only cross-target compilation gate: Stadia XUSB codec -> Cortex-M7 object.

This builds an ELF32 ARM *relocatable object only*. It cannot be flashed or booted.
No SDK, device access, bootloader operations, network, fuse or USB calls.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


class ArmObjectError(ValueError):
    pass


SYMBOLS = (
    "stadia_xusb_from_bruce_hid",
    "stadia_xusb_from_bruce_raw",
    "stadia_xusb_rumble_to_bruce",
)


def read_elf_arm_object(content: bytes) -> dict[str, object]:
    """ELF32 little-endian metadata and defined external API, without running code."""
    if not isinstance(content, bytes) or len(content) < 52:
        raise ArmObjectError("ELF header truncated")
    if content[:6] != b"\x7fELF\x01\x01":
        raise ArmObjectError("Expected ELF32 little-endian")
    fields = struct.unpack_from('<HHIIIIIHHHHHH', content, 16)
    e_type, machine, _version, entry, _phoff, shoff, flags, _ehsz, _phent, _phnum, shentsz, shnum, _shstrndx = fields
    if e_type != 1 or machine != 40 or entry != 0:
        raise ArmObjectError("Expected relocatable ARM object, not a firmware executable")
    if flags & 0xFF000000 != 0x05000000:
        raise ArmObjectError("Expected ARM EABI version 5")
    if not 1 <= shnum <= 1000 or shentsz != 40 or shoff + shnum * shentsz > len(content):
        raise ArmObjectError("Invalid ELF section table")
    sections = [struct.unpack_from('<IIIIIIIIII', content, shoff + 40*i) for i in range(shnum)]
    symbols: set[str] = set()
    undefined: set[str] = set()
    for sec in sections:
        _name, stype, _flags, _addr, off, size, link, _info, _align, entsize = sec
        if stype != 2:
            continue
        if not (0 <= link < shnum and entsize == 16 and off + size <= len(content) and size % 16 == 0):
            raise ArmObjectError("Bad symtab section")
        strsec = sections[link]
        stroff, strlen = strsec[4], strsec[5]
        if stroff + strlen > len(content):
            raise ArmObjectError("Bad string table")
        strs = content[stroff:stroff + strlen]
        for x in range(off, off+size, 16):
            name_idx, _value, _sz, info, _other, shndx = struct.unpack_from('<IIIBBH', content, x)
            if not name_idx:
                continue
            if name_idx >= len(strs):
                raise ArmObjectError("Bad symbol name pointer")
            end = strs.find(b'\0', name_idx)
            if end == -1:
                raise ArmObjectError("Unterminated symbol name")
            symbol = strs[name_idx:end].decode('ascii', 'replace')
            if info >> 4 == 1:
                (undefined if shndx == 0 else symbols).add(symbol)
    missing = set(SYMBOLS) - symbols
    if missing:
        raise ArmObjectError("Missing codec exports: " + ','.join(sorted(missing)))
    return {
        "format": "ELF32 little-endian relocatable ARM object",
        "machine": "EM_ARM", "eabi_version": 5,
        "exported_codec_symbols": sorted(set(SYMBOLS)),
        "undefined_runtime_symbols": sorted(undefined),
        "only_codec_functions_targeted": True,
        "contains_real_usb_device_stack": False,
        "is_bootable_image": False,
        "signed_for_retail_hab": False,
    }


def compile_arm_object(source: Path, header_dir: Path, shim_dir: Path, output_dir: Path) -> dict[str, object]:
    """Execute local compiler, never an uploaded device tool or flashing utility."""
    compiler = shutil.which('clang')
    if compiler is None:
        raise FileNotFoundError('clang cross-target driver is not available')
    for p in (source, header_dir / 'stadia_xusb_codec.h', shim_dir / 'string.h'):
        if not p.is_file():
            raise FileNotFoundError(str(p))
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / 'stadia_xusb_codec_cortex_m7.o'
    cmd = [compiler, '--target=armv7em-none-eabi', '-mcpu=cortex-m7', '-mthumb', '-mfloat-abi=soft',
           '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-std=c11',
           '-Wall', '-Wextra', '-Werror', '-I', str(shim_dir), '-I', str(header_dir),
           '-c', str(source), '-o', str(dest)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=40, check=False)
    if p.returncode:
        raise RuntimeError(f'Cross compilation failed ({p.returncode}): {p.stderr[:2000]}')
    data = dest.read_bytes()
    if len(data) > 100_000:
        raise ArmObjectError('Unexpected object size')
    result = read_elf_arm_object(data)
    result.update({"sha256": hashlib.sha256(data).hexdigest(),
                   "size_bytes": len(data),
                   "compiler_target": 'armv7em-none-eabi/cortex-m7/soft-float',
                   "compiler_first_line": subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
                   "installed_on_controller": False, "actual_hardware_execution_tested": False})
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codec-dir', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    result = compile_arm_object(args.codec_dir / 'stadia_xusb_codec.c', args.codec_dir,
                                Path(__file__).parent / 'arm_phase103_headers', args.out_dir)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
