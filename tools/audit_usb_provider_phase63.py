"""SHA-pinned offline provider/configuration and flag-initialization audit.

Executes selected original fragments with synthetic RAM, object/loop-boundary
inputs and explicit helper stubs. No live RAM, device I/O or firmware writes.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_descriptor_match_phase62 import BASE, FLAG_A, FLAG_B, verify_selector

GLOBAL = 0x200064C0
OWNER = GLOBAL + 0x3DE8
RECORDS = GLOBAL + 0x3DB4
PROVIDER = GLOBAL + 0x3DE4
PROVIDER_SLOT = GLOBAL + 0x3E74
TABLE = 0x60105B88
INITIALIZER = 0x60073BF0
PINS = {
    (0x600748EC, 0x600748F6): {
        0x600748EE: ('ldr', 'r4, [pc, #0x14]'),
        0x600748F0: ('mov', 'r0, r4'),
        0x600748F2: ('bl', '#0x60073bf0'),
    },
    (INITIALIZER, INITIALIZER+8): {
        0x60073BF4: ('mov', 'r4, r0'),
    },
    (0x60073D80, 0x60073D8C): {
        0x60073D80: ('add.w', 'r6, r4, #0x3dc0'),
        0x60073D8A: ('adds', 'r6, #0x24'),
    },
    (0x60073DE0, 0x60073E08): {
        0x60073DE0: ('add.w', 'sl, r4, #0x3d80'),
        0x60073DE6: ('add.w', 'sl, sl, #0x34'),
        0x60073DEE: ('mov', 'r7, sl'),
        0x60073DF0: ('cmp', 'r7, r6'),
        0x60073DF2: ('beq', '#0x60073e44'),
        0x60073DF4: ('ldr', 'r0, [r8, #4]!'),
        0x60073DFC: ('blx', 'r3'),
        0x60073DFE: ('ldm', 'r0, {r0, r1, r2}'),
        0x60073E00: ('stm.w', 'r7, {r0, r1, r2}'),
        0x60073E04: ('adds', 'r7, #0xc'),
        0x60073E06: ('b', '#0x60073df0'),
    },
    (0x60073E44, 0x60073E76): {
        0x60073E48: ('ldr', 'r3, [pc, #0x35c]'),
        0x60073E4E: ('str', 'r3, [r7]'),
        0x60073E64: ('sub.w', 'r7, r7, sl'),
        0x60073E6C: ('lsrs', 'r7, r7, #2'),
    },
    (0x60073E94, 0x60073EF4): {
        0x60073E94: ('movw', 'r3, #0x3de8'),
        0x60073E9E: ('adds', 'r6, r4, r3'),
        0x60073EA4: ('movs', 'r5, #0'),
        0x60073EAC: ('str', 'r3, [r6, #8]'),
        0x60073EB2: ('str.w', 'sl, [r6, #4]'),
        0x60073EB6: ('strb', 'r3, [r6, #0xc]'),
        0x60073EDC: ('muls', 'r7, r3, r7'),
        0x60073EE8: ('mla', 'r7, r3, r7, sl'),
        0x60073EF0: ('strd', 'r7, r5, [r6, #0x8c]'),
    },
    (0x6007408C, 0x600740A0): {
        0x6007408C: ('movw', 'r2, #0x433c'),
        0x60074090: ('adds', 'r3, r4, r2'),
        0x6007409A: ('strb', 'r5, [r3, #8]'),
        0x6007409C: ('strb', 'r5, [r3, #9]'),
    },
    (0x60060DB2, 0x60060DC6): {
        0x60060DB6: ('movw', 'r3, #0x3e74'),
        0x60060DBA: ('ldr', 'r2, [pc, #0x148]'),
        0x60060DBE: ('ldr', 'r0, [r2, r3]'),
        0x60060DC0: ('ldr', 'r3, [r0]'),
        0x60060DC2: ('ldr', 'r3, [r3]'),
        0x60060DC4: ('blx', 'r3'),
    },
}
LITERALS = {0x60074904: GLOBAL, 0x600741A8: TABLE,
            0x60105B88: 0x600619BD, 0x600741C8: 0x60060D55,
            0x60060F04: GLOBAL, 0x600741CC: 0x2AAAAAAB}


def verify_pins(image):
    for (start, end), pins in PINS.items():
        rows = {r['pc']: (r['m'], r['op']) for r in decode(image, start, end)}
        for pc, expected in pins.items():
            if rows.get(pc) != expected:
                raise ValueError(f'Phase63 semantic drift at {pc:#x}: {rows.get(pc)}')
    for address, value in LITERALS.items():
        if struct.unpack_from('<I', image, address-BASE)[0] != value:
            raise ValueError(f'Phase63 literal drift at {address:#x}')
    table = 0x60060D6A
    destination = table + 2*struct.unpack_from('<H', image, table-BASE+2*11)[0]
    if destination != 0x60060DB2:
        raise ValueError('Phase63 internal event 12 table drift')
    return destination


def emulate_chain(image):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5,
        UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R10,
    )
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x110000)
    uc.mem_write(BASE, image)
    uc.mem_map(0x20000000, 0x30000)
    uc.mem_map(0x10000000, 0x1000)
    uc.reg_write(UC_ARM_REG_SP, 0x2002E000)
    uc.reg_write(UC_ARM_REG_R4, GLOBAL)
    uc.reg_write(UC_ARM_REG_R5, 0x20010000)
    uc.reg_write(UC_ARM_REG_R6, PROVIDER)
    uc.reg_write(UC_ARM_REG_R7, PROVIDER)
    uc.reg_write(UC_ARM_REG_R10, RECORDS)
    # Explicit synthetic boundary: four copied records ending at PROVIDER.
    # The record-producing objects and their true contents are not emulated.
    uc.mem_write(RECORDS, bytes(48))
    uc.mem_write(FLAG_A, b'\xa5\x5a')
    helper_calls, writes, reached = [], [], []
    stage = ['metadata']
    boundaries = {'metadata': (0x60073E44, 0x60073EF4),
                  'flags': (0x6007408C, 0x600740A0)}
    allowed_helpers = {0x6013CF90, 0x6013D3A0, 0x6005BDAC, 0x600DFFE8, 0x6010165C}

    def hook(machine, address, size, user):
        reached.append(address)
        if stage[0] in boundaries and address == boundaries[stage[0]][1]:
            machine.emu_stop()
            return
        if stage[0] == 'dispatch' and address == 0x10000000:
            machine.emu_stop()
            return
        if address in allowed_helpers:
            helper_calls.append(dict(stage=stage[0], target=hex(address),
                r0=hex(machine.reg_read(UC_ARM_REG_R0)), r1=hex(machine.reg_read(UC_ARM_REG_R1))))
            if address == 0x6005BDAC:
                machine.reg_write(UC_ARM_REG_R0, 0x20010000)
            elif address == 0x600DFFE8:
                machine.reg_write(UC_ARM_REG_R0, 0)
            # Init copy/clear helpers are no-op stubs returning their R0 input.
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
            return
        if stage[0] in boundaries:
            lo, hi = boundaries[stage[0]]
            if not lo <= address < hi:
                raise ValueError(f'Unexpected fragment instruction {address:#x}')
        elif not (0x60060D54 <= address < 0x60060F04 or 0x600619BC <= address < 0x60061A2C):
            raise ValueError(f'Unexpected dispatch execution {address:#x}')

    def memory_hook(machine, access, address, size, value, user):
        if address in (OWNER+4, OWNER+8, OWNER+12, PROVIDER, PROVIDER_SLOT, FLAG_A, FLAG_B):
            writes.append(dict(stage=stage[0], pc=hex(machine.reg_read(UC_ARM_REG_PC)),
                address=hex(address), size=size, value=hex(value)))

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, memory_hook)
    uc.emu_start(0x60073E45, 0x60073EF6, count=300)
    if reached[-1] != 0x60073EF4:
        raise ValueError('Metadata fragment did not reach its bound')
    expected = {PROVIDER: TABLE, OWNER+4: RECORDS, OWNER+8: 0x60060D55, PROVIDER_SLOT: PROVIDER}
    actual = {address: struct.unpack('<I', bytes(uc.mem_read(address, 4)))[0] for address in expected}
    if actual != expected or bytes(uc.mem_read(OWNER+12, 1)) != b'\x04':
        raise ValueError('Original metadata fragment did not construct expected chain')
    if uc.reg_read(UC_ARM_REG_R5) != 0:
        raise ValueError('Original MOVS did not establish R5 zero')
    # This is a separate fragment; intervening initialization is NOT executed.
    stage[0] = 'flags'
    uc.reg_write(UC_ARM_REG_R4, GLOBAL)
    uc.emu_start(0x6007408D, 0x600740A2, count=30)
    if reached[-1] != 0x600740A0 or bytes(uc.mem_read(FLAG_A, 2)) != b'\0\0':
        raise ValueError('Flag-writer fragment failed')
    stage[0] = 'dispatch'
    output = 0x20022000
    uc.reg_write(UC_ARM_REG_R0, 0x20010000)
    uc.reg_write(UC_ARM_REG_R1, 12)  # internal event; not a USB bRequest.
    uc.reg_write(UC_ARM_REG_R2, output)
    uc.reg_write(UC_ARM_REG_LR, 0x10000001)
    uc.emu_start(0x60060D55, 0x10000002, count=300)
    if reached[-1] != 0x10000000 or 0x600619BC not in reached or 0x60060DC4 not in reached:
        raise ValueError('Indirect original dispatch did not return through selector')
    pointer, length = struct.unpack('<II', bytes(uc.mem_read(output, 8)))
    if (pointer, length) != (0x6011E45A, 80) or uc.reg_read(UC_ARM_REG_R0) != 0:
        raise ValueError('Original dispatch result differs from phase61 descriptor')
    return dict(synthetic_record_count=4,
        metadata_words={hex(k): hex(v) for k, v in actual.items()},
        class_count_byte=4, flag_initial_bytes='a55a', flag_final_bytes='0000',
        observed_original_writes=writes, internal_event=12,
        original_indirect_selector_reached=True, descriptor_pointer=hex(pointer), descriptor_bytes=length,
        returned_zero=True, stubbed_calls=helper_calls,
        limits=['Loop exit/R4/SL/R7 inputs are synthetic, not an execution of the complete initializer.',
                'The four class records are synthetic zero bytes; actual record identities remain unresolved.',
                'Init clear/copy helpers are no-op stubs with unchanged R0; their writes/effects are not modeled.',
                'Flag-writer fragment is separate; intervening code is not executed. R5 zero is carried from the metadata fragment.',
                'Dispatch event 12 is supplied internally in emulation, not sent to the physical USB device.',
                'The selector helper returns zero by stub, not a measured physical state.'])


def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('Phase63 exact SHA-pinned OEM image required')
    verify_selector(image)
    target = verify_pins(image)
    return dict(phase=63, image_sha256=IMAGE_SHA256, exact_image_hash_verified=True,
        caller_argument=dict(call_pc='0x600748f2', target=hex(INITIALIZER), argument_r0=hex(GLOBAL),
                             literal='0x60074904', saved_as_r4='0x60073bf4'),
        owner=hex(OWNER), class_array=hex(RECORDS), provider_object=hex(PROVIDER),
        provider_slot=hex(PROVIDER_SLOT), provider_table=hex(TABLE), internal_event_12_target=hex(target),
        flag_store_sites={'0x6007409a': hex(FLAG_A), '0x6007409c': hex(FLAG_B)},
        synthetic_chain=emulate_chain(image),
        limits=['Signed static path and bounded virtual fragment execution only; no installed RAM measurements.',
                'Four internal class records do not mean four advertised USB interfaces.',
                'Internal selector 10 activation and actual class array contents remain unverified.',
                'No exhaustive writer census; later flag updates, aliases, wide writes and bulk initialization are not excluded.',
                'No physical host-to-callback proof, unsigned execution, HAB bypass or native console compatibility.',
                'No device I/O, flash writes, eFuse writes, mode changes or full firmware published.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    result = json.dumps(audit(args.image.read_bytes()), indent=2) + '\n'
    if args.out:
        args.out.write_text(result, encoding='utf-8')
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
