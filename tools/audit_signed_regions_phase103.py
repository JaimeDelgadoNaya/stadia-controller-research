"""Inspect NXP IVT/CSF offsets of offline public firmware files only.

No signature verification, no fuse reading, no bootloader installation or SDP.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct


class ImageFormatError(ValueError):
    pass


def describe_image(image: bytes, ivt_offset: int, *, label: str) -> dict[str, object]:
    if not isinstance(image, bytes) or not isinstance(ivt_offset, int) or ivt_offset < 0 or ivt_offset+32 > len(image):
        raise ImageFormatError('Image or IVT position is invalid')
    if image[ivt_offset:ivt_offset+4] != bytes.fromhex('d1002041'):
        raise ImageFormatError('Unsupported NXP IVT header')
    head = struct.unpack_from('<8I', image, ivt_offset)
    _hdr, entry, r1, _dcd, boot_data, self_ptr, csf_ptr, r2 = head
    if r1 or r2 or not self_ptr or not boot_data or not entry or self_ptr < ivt_offset:
        raise ImageFormatError('Malformed IVT pointers')
    image_base = self_ptr - ivt_offset
    bd_offset = boot_data - image_base
    if not 0 <= bd_offset <= len(image)-12:
        raise ImageFormatError('Boot data outside image')
    boot_start, boot_len, _plugin = struct.unpack_from('<3I',image,bd_offset)
    csf_offset = csf_ptr - image_base if csf_ptr else None
    csf_included = csf_offset is not None and 0 <= csf_offset < len(image)
    csf_header_present = bool(csf_included and csf_offset+4 <= len(image) and image[csf_offset] == 0xd4)
    return {
        'name':label, 'file_bytes':len(image), 'sha256':sha256(image).hexdigest(),
        'image_base_address':f'0x{image_base:08x}',
        'ivt_file_offset':f'0x{ivt_offset:x}',
        'entry_address':f'0x{entry:08x}',
        'boot_image_declared_start':f'0x{boot_start:08x}',
        'boot_image_declared_bytes':boot_len,
        'csf_pointer_address':f'0x{csf_ptr:08x}' if csf_ptr else None,
        'csf_offset_within_flat_image':f'0x{csf_offset:x}' if csf_offset is not None else None,
        'csf_bytes_in_supplied_image':bool(csf_included),
        'csf_header_d4_found':csf_header_present,
        'csf_header_length_only': (int.from_bytes(image[csf_offset+1:csf_offset+3],'big')
                                   if csf_header_present else None),
        'cryptographic_signature_verified':False,
        'fused_trust_anchor_known':False,
        'retail_fuse_state_read':False,
        'permission_to_flash_retail':False,
    }


def read_only_audit(paths: dict[str, tuple[Path,int]]):
    return {name:describe_image(path.read_bytes(),off,label=name)
            for name,(path,off) in paths.items()}


if __name__=='__main__':
    raise SystemExit('Read-only module. Import describe_image; do not flash hardware.')
