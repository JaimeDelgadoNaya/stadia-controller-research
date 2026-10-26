"""Match phase-61 USB descriptors to the exact OEM image, entirely offline.

Optionally execute only the descriptor selector in Unicorn, with explicit
synthetic helper returns and RAM flags. Never opens a device or outputs firmware.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.parse_usb_configuration import parse_configuration

BASE = ASSUMED_XIP_BASE
SIGNED_END = 0xFF000
ENTRY, STOP = 0x600619BC, 0x60061A2C
RAM_BASE = 0x200064C0
FLAG_A, FLAG_B = RAM_BASE + 0x4344, RAM_BASE + 0x4345
VARIANTS = (
    (0xDE45A, 80, 2, 0x60061A24, 0x60061A4C),
    (0xDE4AA, 40, 1, 0x600619DC, 0x60061A34),
    (0xDE4D2, 204, 4, 0x60061A1C, 0x60061A48),
    (0xDE59E, 287, 5, 0x60061A06, 0x60061A40),
)
# Semantic checks constrain the original path, not just matching literals.
PINS = {
    ENTRY: ('push', '{r4, lr}'),
    0x600619BE: ('mov', 'r4, r1'),
    0x600619C0: ('bl', '#0x6005bdac'),
    0x600619C4: ('movs', 'r1, #7'),
    0x600619C6: ('add.w', 'r0, r0, #0x448'),
    0x600619CA: ('bl', '#0x600dffe8'),
    0x600619CE: ('cbz', 'r0, #0x600619e8'),
    0x600619DE: ('str', 'r3, [r4]'),
    0x600619E0: ('movs', 'r3, #0x28'),
    0x600619E2: ('str', 'r3, [r4, #4]'),
    0x600619E4: ('movs', 'r0, #0'),
    0x600619E6: ('pop', '{r4, pc}'),
    0x600619E8: ('ldr', 'r3, [pc, #0x4c]'),
    0x600619EA: ('movw', 'r2, #0x4344'),
    0x600619EE: ('ldrb', 'r2, [r3, r2]'),
    0x600619F0: ('cbz', 'r2, #0x60061a24'),
    0x600619F2: ('movw', 'r2, #0x4345'),
    0x600619F6: ('ldrb', 'r3, [r3, r2]'),
    0x600619F8: ('cbz', 'r3, #0x60061a10'),
    0x60061A08: ('str', 'r3, [r4]'),
    0x60061A0A: ('movw', 'r3, #0x11f'),
    0x60061A0E: ('b', '#0x600619e2'),
    0x60061A1E: ('str', 'r3, [r4]'),
    0x60061A20: ('movs', 'r3, #0xcc'),
    0x60061A22: ('b', '#0x600619e2'),
    0x60061A26: ('str', 'r3, [r4]'),
    0x60061A28: ('movs', 'r3, #0x50'),
    0x60061A2A: ('b', '#0x600619e2'),
}


def occurrences(blob, needle):
    if not needle:
        raise ValueError('Empty search pattern')
    result, start = [], 0
    while (offset := blob.find(needle, start)) >= 0:
        result.append(offset)
        start = offset + 1
    return result


def verify_selector(image):
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    instructions = list(decoder.disasm(image[ENTRY-BASE:STOP-BASE], ENTRY))
    rows = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    for pc, expected in PINS.items():
        if rows.get(pc) != expected:
            raise ValueError(f'Selector semantic drift at {pc:#x}')
    for offset, length, count, load, literal in VARIANTS:
        ins = next(i for i in instructions if i.address == load)
        # All four selected descriptor loads are Thumb16 PC-relative LDRs.
        halfword = int.from_bytes(ins.bytes, 'little')
        if halfword & 0xF800 != 0x4800 or ((load+4) & ~3) + (halfword & 255)*4 != literal:
            raise ValueError('Descriptor literal-load drift')
        if struct.unpack_from('<I', image, literal-BASE)[0] != BASE+offset:
            raise ValueError('Descriptor pointer drift')
    if struct.unpack_from('<I', image, 0x60061A38-BASE)[0] != RAM_BASE:
        raise ValueError('Flag base drift')


def conditional_variant(helper_result, flag_a, flag_b):
    """Expected branch outcomes, independently checked by original-code emulation."""
    if helper_result:
        return 0xDE4AA, 40
    if not flag_a:
        return 0xDE45A, 80
    return (0xDE59E, 287) if flag_b else (0xDE4D2, 204)


def emulate_case(image, helper_result, flag_a, flag_b):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x110000)
    uc.mem_write(BASE, image)
    uc.mem_map(0x20000000, 0x20000)
    uc.mem_map(0x10000000, 0x1000)
    output, sentinel = 0x20018000, 0x10000000
    uc.mem_write(FLAG_A, bytes([flag_a, flag_b]))
    uc.reg_write(UC_ARM_REG_R1, output)
    uc.reg_write(UC_ARM_REG_SP, 0x2001F000)
    uc.reg_write(UC_ARM_REG_LR, sentinel | 1)
    calls, returned = [], []

    def hook(machine, address, size, user):
        if address == sentinel:
            returned.append(True)
            machine.emu_stop()
        elif address in (0x6005BDAC, 0x600DFFE8, 0x6010165C):
            calls.append(dict(target=hex(address), r0=hex(machine.reg_read(UC_ARM_REG_R0)),
                              r1=hex(machine.reg_read(UC_ARM_REG_R1))))
            if address == 0x6005BDAC:
                machine.reg_write(UC_ARM_REG_R0, 0x20001000)
            elif address == 0x600DFFE8:
                machine.reg_write(UC_ARM_REG_R0, helper_result)
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif not ENTRY <= address < STOP:
            raise ValueError(f'Unmodeled execution at {address:#x}')

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(ENTRY | 1, sentinel+2, count=200)
    if not returned:
        raise ValueError('Selector did not return within instruction bound')
    pointer, length = struct.unpack('<II', bytes(uc.mem_read(output, 8)))
    expected_offset, expected_length = conditional_variant(helper_result, flag_a, flag_b)
    if (pointer, length) != (BASE+expected_offset, expected_length) or uc.reg_read(UC_ARM_REG_R0) != 0:
        raise ValueError('Emulation differs from verified branch model')
    return dict(synthetic_helper_result=helper_result, synthetic_flag_a=flag_a,
                synthetic_flag_b=flag_b, output_pointer=hex(pointer), output_length=length,
                returned=True, helper_calls_stubbed=calls)


def audit(image, live, emulate=False):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('Exact SHA-pinned Bruce OEM image required')
    full = bytes.fromhex(live['hub']['configuration'])
    function = bytes.fromhex(live['winusb_function_view']['configuration'])
    parse_configuration(full)
    parse_configuration(function)
    verify_selector(image)
    variants = []
    for offset, length, count, load, literal in VARIANTS:
        descriptor = image[offset:offset+length]
        parsed = parse_configuration(descriptor)
        if parsed['declared_interfaces'] != count:
            raise ValueError('OEM interface-count drift')
        variants.append(dict(file_offset=hex(offset), xip_address=hex(BASE+offset),
            length=length, descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),
            declared_interfaces=count, usb_interface_classes=sorted({i['usb_class'] for i in parsed['interfaces']}),
            exact_live_hub_match=descriptor == full, pointer_load_pc=hex(load),
            pointer_literal_pc=hex(literal), parsed=parsed))
    return dict(phase=62, image_sha256=IMAGE_SHA256, exact_image_hash_verified=True,
        source='https://raw.githubusercontent.com/StadiaMemories/firmware/main/bruce_pvt_a_prod_signed.bin',
        comparison_scope='authenticated OEM application content before file offset 0xff000',
        live_hub_sha256=hashlib.sha256(full).hexdigest(),
        exact_full_descriptor_matches=[hex(o) for o in occurrences(image[:SIGNED_END], full)],
        exact_winusb_view_matches=[hex(o) for o in occurrences(image[:SIGNED_END], function)],
        selector_entry=hex(ENTRY), selector_flag_addresses=[hex(FLAG_A), hex(FLAG_B)],
        selector_helper_arguments='0x600dffe8 receives singleton_return+0x448 and 7; meaning unresolved',
        variants=variants,
        emulation=[emulate_case(image, h, a, b) for h in (0,1) for a in (0,1) for b in (0,1)] if emulate else [],
        limits=['Exact descriptors match, not the complete installed firmware hash.',
                'Original selector instructions are executed only in bounded synthetic emulation.',
                'Singleton, helper and logging calls are stubbed; their effects and runtime state are unknown.',
                'RAM flags are not measured on the physical controller and no flag setter is traced.',
                'Internal class selector 10 activation, callback invocation and USB-to-code path remain unproven.',
                'No device I/O, firmware writes, HAB bypass or native console interoperability.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('--live', type=Path, default=Path('evidence/usb-enumeration-phase61.json'))
    p.add_argument('--emulate', action='store_true')
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    report = audit(args.image.read_bytes(), json.loads(args.live.read_text(encoding='utf-8-sig')), args.emulate)
    text = json.dumps(report, indent=2) + '\n'
    if args.out:
        args.out.write_text(text, encoding='utf-8')
    else:
        print(text, end='')


if __name__ == '__main__':
    main()
