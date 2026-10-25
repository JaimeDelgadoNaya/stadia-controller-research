"""Offline SHA-locked Bruce USB dispatch and startup-relocation audit.

Reports selected pointer/control-flow facts only. No device APIs or firmware
bytes are output. Storage addresses must not be confused with ITCM runtime PCs.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from tools.audit_app_message_role import inspect as inspect_role
except ModuleNotFoundError:
    from audit_app_message_role import inspect as inspect_role

BASE = 0x60040000
ITCM_SOURCE_OFFSET = 0x81C
ITCM_LENGTH = 0xBDF8
DATA_SOURCE_OFFSET = 0xFD5A8
DATA_DESTINATION = 0x20002740
DATA_END = 0x20003FD8
POINTERS = {
    0x5F4: 0x6013D5A8, 0x5F8: DATA_DESTINATION, 0x5FC: DATA_END,
    0x60C: 0x6004081C, 0x610: 0, 0x614: ITCM_LENGTH,
    0x2A40: 0x200064C0, 0x2A48: 0x20009E00,
    0x18C00: 0x600D36B7, 0x18C04: 0x20009E00,
    0x18C08: 0x600D3687, 0x18C0C: 0x60058B65,
    0xFE058: 0x21A1, 0xFE05C: 0, 0xFE060: 0x200031C4,
    0x22630: 0x200031F0, 0xBE30: 0x600D5401,
}
REGIONS = [
    (0x566, 0x5AE, 'f1e6bfd54f140748be0fbcdf7396c942b76e41988e39d8206d9e5a015d3fdd8c'),
    (0x29BC, 0x2A54, 'e500608f6da9e151a602691e998661ad36da4ea1309f1c583243d4956470e167'),
    (0x93686, 0x9368E, 'b829674cb12338c0fac301b1215184ee36246d2d584135a81942c0453111ceb2'),
    (0x9543C, 0x95456, 'dff79e8631e69c476d67ffadbf5d9a33caa21231c04b0c0ba4d12fa20c633ec9'),
    (0xFE000, 0xFE064, '0e39b5b64012b3a09b6690844e3f8de7eef2a303ab0acbc3772864810b0a1d67'),
]
ANCHORS = {
    0x60040570: ('ldrlt', 'r0, [r1], #4'),
    0x60040574: ('strlt', 'r0, [r2], #4'),
    0x600405A4: ('ldrlt', 'r0, [r1], #4'),
    0x600405A8: ('strlt', 'r0, [r2], #4'),
    0x21A0: ('subs', 'r3, r1, #1'),
    0x21AA: ('tbb', '[pc, r3]'),
    0x21DE: ('cbz', 'r2, #0x2214'),
    0x21E0: ('ldr', 'r2, [r0, #4]'),
    0x21E2: ('adds', 'r1, r2, #1'),
    0x21E4: ('beq', '#0x21f6'),
    0x21EA: ('ldr', 'r4, [r3, r1]'),
    0x21EC: ('ldr', 'r1, [r0]'),
    0x21F2: ('ldr', 'r0, [r3, r0]'),
    0x21F4: ('blx', 'r4'),
    0x21F8: ('bl', '#0xb610'),
    0xB610: ('ldr.w', 'pc, [pc, #-0x0]'),
    0x600D3686: ('mov', 'r3, r0'),
    0x600D3688: ('mov', 'r0, r1'),
    0x600D368A: ('mov', 'r1, r2'),
    0x600D368C: ('bx', 'r3'),
    0x600D5440: ('add.w', 'r3, r0, #8'),
    0x600D5444: ('ldm', 'r1, {r0, r1}'),
    0x600D5446: ('stm.w', 'r3, {r0, r1}'),
    0x600D5400: ('movs', 'r3, #0x40'),
    0x600D5402: ('movs', 'r1, #3'),
    0x600D5408: ('b.w', '#0x600d0e38'),
    0x6006262C: ('ldr', 'r0, [pc, #0]'),
    0x6006262E: ('bx', 'lr'),
}


def itcm_runtime(offset):
    if not ITCM_SOURCE_OFFSET <= offset < ITCM_SOURCE_OFFSET + ITCM_LENGTH:
        raise ValueError('Outside startup ITCM copy')
    return offset - ITCM_SOURCE_OFFSET


def initialized_ram(offset):
    length = DATA_END - DATA_DESTINATION
    if not DATA_SOURCE_OFFSET <= offset < DATA_SOURCE_OFFSET + length:
        raise ValueError('Outside startup initialized-data copy')
    return DATA_DESTINATION + offset - DATA_SOURCE_OFFSET


def validate_semantics(decoded):
    for address, semantic in ANCHORS.items():
        if decoded.get(address) != semantic:
            raise ValueError(f'Changed dispatch semantics at 0x{address:08x}')


def inspect(image):
    role = inspect_role(image)  # mandatory exact image/hash and previous path audit
    for start, end, expected in REGIONS:
        if hashlib.sha256(image[start:end]).hexdigest() != expected:
            raise ValueError('Changed dispatch region fingerprint')
    for offset, expected in POINTERS.items():
        if struct.unpack_from('<I', image, offset)[0] != expected:
            raise ValueError('Changed startup or dispatch literal')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    decoded = {}
    windows = [(0x566, 0x5AE, BASE + 0x566),
               (0x29BC, 0x29CA, itcm_runtime(0x29BC)),
               (0x29F2, 0x2A1A, itcm_runtime(0x29F2)),
               (0xBE2C, 0xBE30, itcm_runtime(0xBE2C)),
               (0x93686, 0x9368E, 0x600D3686),
               (0x9543C, 0x95456, 0x600D543C),
               (0x95400, 0x9540C, 0x600D5400),
               (0x2262C, 0x22630, 0x6006262C)]
    for start, end, runtime in windows:
        decoded.update({i.address: (i.mnemonic, i.op_str)
                        for i in decoder.disasm(image[start:end], runtime)})
    validate_semantics(decoded)
    event_two = itcm_runtime(0x29CA) + image[0x29CB] * 2
    if event_two != itcm_runtime(0x29F2):
        raise ValueError('Internal event-2 dispatch changed')
    if 0x200064C0 + 0x3950 != 0x20009E10:
        raise AssertionError('Callback alias arithmetic')
    return {
        'analysis_date': '2026-10-25', 'offline_only': True,
        'sample_kind': role['sample_kind'], 'sha256': role['sha256'],
        'address_correction': {
            'startup': '0x6004059a..0x600405ac copies to ITCM',
            'source_image_address': '0x6004081c', 'destination': '0x00000000',
            'length': '0x0000bdf8',
            'dispatcher_file_offset': '0x000029bc',
            'dispatcher_stored_image_address': '0x600429bc',
            'dispatcher_runtime_address': '0x000021a0',
            'reason': 'PC-relative calls in copied code must be decoded at runtime PC',
        },
        'initialized_callback': {
            'source_image_address': '0x6013e058',
            'destination_ram': f'0x{initialized_ram(0xFE058):08x}',
            'thumb_callback': '0x000021a1',
            'configuration_getter': '0x6006262c returns 0x200031f0',
            'live_registration_or_invocation': 'not measured',
        },
        'registration': {
            'wrapper': '0x60058bdc',
            'helper_0x600d543c': 'copies callback/context pair to object +8, not +0x10',
            'object': '0x20009e00',
            'separate_direct_stores': {
                '+0x10': 'Thumb thunk 0x600d3687',
                '+0x14': 'Thumb tag-5 parser 0x60058b65',
            },
        },
        'static_receive_chain': {
            'internal_event': 2,
            'event_is_host_command': False,
            'dispatcher': '0x000021a0 -> event block 0x000021d6',
            'guard': 'global byte at 0x2000a33c nonzero',
            'length_guard': 'callback skipped for length 0xffffffff sentinel',
            'buffer_and_length': 'event-data words +0 and +4',
            'function_alias': '0x200064c0 + 0x3950 = object +0x10',
            'context_alias': '0x200064c0 + 0x3954 = object +0x14',
            'invoke': '0x000021f4 BLX -> 0x600d3686 argument thunk -> 0x60058b64',
            'tag5_effect': role['classification'],
        },
        'receive_rearm': {
            'call': '0x000021f8 -> ITCM veneer 0x0000b610 -> 0x600d5400',
            'endpoint_argument': 3, 'length_argument': 64,
            'next_helper': '0x600d0e38',
            'actual_endpoint_direction_and_packet_completion_source': 'not independently established by this bounded audit',
        },
        'limits': [
            'Static conditional callback path; live host-to-callback invocation not measured',
            'Internal event 2 is not a proven USB host opcode or bRequest',
            'Endpoint argument 3 and length 64 do not alone prove endpoint direction or HID report semantics',
            'No generic vendor request receiver, flash-update route or arbitrary execution established',
            'No device IO, signature bypass, installable patch or Switch 2 compatibility',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    report = json.dumps(inspect(args.image.read_bytes()), indent=2) + '\n'
    if args.out:
        args.out.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
