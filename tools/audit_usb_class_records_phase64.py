"""Recover OEM class records through original constructor/producer execution.

Offline only. Startup data comes from the exact SHA-pinned update, never from
live RAM. Explicit helper stubs and an injected selector handoff bound the claim.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_app_usb_dispatch import DATA_SOURCE_OFFSET, DATA_DESTINATION, DATA_END
from tools.audit_bruce_class_selector_verified import verified_rom_table, ROM_TABLE_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_provider_phase63 import BASE, GLOBAL, OWNER, RECORDS, verify_pins

# object offset, vtable, producer, return-literal address, original record,
# original record file offset, callback, descriptor, selector.
SOURCES = (
    (0x3A30, 0x60105A5C, 0x600613F4, 0x600613F8, 0x200030F4, 0xFDF5C, 0x600613FD, 0x20003100, 10),
    (0x3940, 0x60105F30, 0x6006262C, 0x60062630, 0x200031F0, 0xFE058, 0x000021A1, 0x200031C4, 1),
    (0x39C4, 0x60105A40, 0x60061104, 0x60061108, 0x200030E8, 0xFDF50, 0x60061249, 0x200030A0, 2),
    (0x3A60, 0x60105F1C, 0x60061E08, 0x60061E0C, 0x2000312C, 0xFDF94, 0x600624F9, 0x20003138, 4),
)


def initialized_offset(address, size=1):
    if size < 1 or not DATA_DESTINATION <= address <= DATA_END-size:
        raise ValueError('Outside OEM startup initialized-data mapping')
    return DATA_SOURCE_OFFSET + address-DATA_DESTINATION


def verify_sources(image):
    verify_pins(image)
    registry = verified_rom_table(image)
    rows = []
    for obj, table, method, literal, record, source, callback, descriptor, selector in SOURCES:
        instructions = decode(image, method, method+4)
        if [(i['m'], i['op']) for i in instructions] != [('ldr', 'r0, [pc, #0]'), ('bx', 'lr')]:
            raise ValueError('Producer method semantic drift')
        if ((method+4) & ~3) != literal or struct.unpack_from('<I', image, literal-BASE)[0] != record:
            raise ValueError('Producer return-literal drift')
        if struct.unpack_from('<I', image, table-BASE)[0] != method | 1:
            raise ValueError('Producer vtable drift')
        if initialized_offset(record, 12) != source:
            raise ValueError('Record source mapping drift')
        words = struct.unpack_from('<III', image, source)
        if words != (callback, 0, descriptor):
            raise ValueError('Original record words drift')
        if image[initialized_offset(descriptor+4)] != selector:
            raise ValueError('Original descriptor selector drift')
        target = next(row['method_0'] for row in registry if row['selector_at_plus_0xc'] == selector)
        rows.append(dict(object=hex(GLOBAL+obj), table=hex(table), producer=hex(method),
            producer_return_literal=hex(literal), original_record=hex(record),
            original_record_source_offset=hex(source), callback=hex(callback),
            descriptor=hex(descriptor), selector=selector, selected_method_0=target))
    return rows


def emulate(image, sources, *, return_ram=False):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1,
        UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R5, UC_ARM_REG_R6,
        UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R11,
    )
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE, 0x110000)
    uc.mem_write(BASE, image)
    uc.mem_map(0x20000000, 0x30000)
    data = image[DATA_SOURCE_OFFSET:DATA_SOURCE_OFFSET+DATA_END-DATA_DESTINATION]
    uc.mem_write(DATA_DESTINATION, data)
    uc.reg_write(UC_ARM_REG_SP, 0x2002E000)
    uc.reg_write(UC_ARM_REG_R0, GLOBAL)
    uc.reg_write(UC_ARM_REG_LR, 0x10000001)
    stage, steps = ['constructor'], []
    calls, produced, stores = [], [], []
    methods = {row['producer'] for row in sources}
    pending = []

    def hook(machine, pc, size, user):
        steps.append(pc)
        if stage[0] == 'constructor':
            if pc == 0x60073EF4:
                machine.emu_stop()
                return
            if pc in (0x6013CF90, 0x600723B4, 0x600D9B6C, 0x6013D3A0):
                a = [machine.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
                calls.append(dict(target=hex(pc), arguments=[hex(v) for v in a],
                    model='bounded byte fill' if pc == 0x6013CF90 else 'no-op; unchanged R0'))
                if pc == 0x6013CF90:
                    if not 0x20000000 <= a[0] <= 0x20030000-a[2] or a[2] > 0x1000:
                        raise ValueError('Fill helper outside bounded virtual SRAM')
                    machine.mem_write(a[0], bytes([a[1] & 255])*a[2])
                machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
                return
            if pc == 0x60073DFC:
                obj = machine.reg_read(UC_ARM_REG_R0)
                table = struct.unpack('<I', bytes(machine.mem_read(obj, 4)))[0]
                pending.append(dict(object=hex(obj), table=hex(table),
                    target=hex(machine.reg_read(UC_ARM_REG_R3))))
            if pc == 0x60073DFE:
                if not pending:
                    raise ValueError('Unexpected producer return')
                row = pending.pop()
                row['returned_original_record'] = hex(machine.reg_read(UC_ARM_REG_R0))
                produced.append(row)
            permitted = (0x60073BF0 <= pc < 0x60073E08 or 0x60073E44 <= pc < 0x60073EF4 or
                         any(int(m,16) <= pc < int(m,16)+4 for m in methods))
            if not permitted:
                raise ValueError(f'Unexpected constructor execution {pc:#x}')
        else:
            if pc == 0x60055194:
                machine.emu_stop()  # never execute any class initializer.
                return
            if not 0x60055170 <= pc < 0x6005519C:
                raise ValueError(f'Unexpected selector execution {pc:#x}')

    def on_write(machine, access, address, size, value, user):
        if RECORDS <= address < RECORDS+48:
            stores.append(dict(pc=hex(machine.reg_read(UC_ARM_REG_PC)),
                address=hex(address), size=size, value=hex(value)))

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.emu_start(0x60073BF1, 0x60073EF6, count=3000)
    if steps[-1] != 0x60073EF4 or pending or len(produced) != 4:
        raise ValueError('Original constructor did not complete four producers')
    original_steps = len(steps)
    copied = []
    for index, (expected, invocation) in enumerate(zip(sources, produced)):
        record = RECORDS+12*index
        source = int(expected['original_record_source_offset'],16)
        actual = bytes(uc.mem_read(record, 12))
        if actual != image[source:source+12]:
            raise ValueError('Original triplet copy differs from signed source')
        if invocation != dict(object=expected['object'], table=expected['table'],
                              target=hex(int(expected['producer'],16) | 1),
                              returned_original_record=expected['original_record']):
            raise ValueError('Original producer path differs from signed sources')
        callback, instance, descriptor = struct.unpack('<III', actual)
        selector = bytes(uc.mem_read(descriptor+4,1))[0]
        if selector != expected['selector']:
            raise ValueError('Copied descriptor class differs')
        copied.append(dict(index=index, destination=hex(record), callback=hex(callback),
            instance_before_class_init=hex(instance), descriptor=hex(descriptor), selector=selector,
            exact_signed_source_bytes=True))
    owner_words = struct.unpack('<II', bytes(uc.mem_read(OWNER+4, 8)))
    if owner_words != (RECORDS, 0x60060D55) or bytes(uc.mem_read(OWNER+12,1)) != b'\x04':
        raise ValueError('Owner metadata differs from expected original construction')

    # Explicit handoff fixture: register/engine checks before this fragment are
    # not executed. Only point the singleton at the constructor-produced config.
    singleton = 0x20004080
    uc.mem_write(singleton+4, struct.pack('<I', OWNER+4))
    stage[0] = 'selector'
    selections = []
    for record, expected in zip(copied, sources):
        uc.reg_write(UC_ARM_REG_R5, singleton)
        uc.reg_write(UC_ARM_REG_R6, bytes(uc.mem_read(OWNER+0x10,1))[0])
        uc.reg_write(UC_ARM_REG_R8, record['index'])
        uc.reg_write(UC_ARM_REG_R11, ROM_TABLE_BASE)
        uc.emu_start(0x60055171, 0x6005519E, count=100)
        pointer = int(record['destination'],16)
        if steps[-1] != 0x60055194 or uc.reg_read(UC_ARM_REG_R3) != int(expected['selected_method_0'],16):
            raise ValueError('Original selector failed to match the original record')
        if (uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)) != (pointer,pointer+4):
            raise ValueError('Original selector argument provenance drift')
        selections.append(dict(index=record['index'], selector=record['selector'],
            method_thumb=hex(uc.reg_read(UC_ARM_REG_R3)), argument_r1=hex(pointer),
            output_pointer_r2=hex(pointer+4), registry_record_offset=uc.reg_read(UC_ARM_REG_R7),
            stopped_before_class_method_call=True))
    result = dict(start='0x60073bf0', stop='0x60073ef4', constructor_instruction_hooks=original_steps,
        producers=produced, copied_records=copied, original_record_stores=stores,
        owner_config=dict(array=hex(owner_words[0]), method=hex(owner_words[1]), count=4),
        selector_matches=selections, helper_calls=calls,
        selector_handoff='Injected singleton+4=owner+4 and fragment registers; engine setup/checks not executed',
        class_methods_executed=False, callbacks_executed=False)
    if return_ram:
        return result, bytes(uc.mem_read(0x20000000, 0x30000))
    return result


def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError('Phase64 exact SHA-pinned OEM image required')
    sources = verify_sources(image)
    data_length = DATA_END-DATA_DESTINATION
    return dict(phase=64, image_sha256=IMAGE_SHA256, exact_image_hash_verified=True,
        startup_data=dict(source_file_offset=hex(DATA_SOURCE_OFFSET), destination=hex(DATA_DESTINATION),
            length=data_length, sha256=hashlib.sha256(image[DATA_SOURCE_OFFSET:DATA_SOURCE_OFFSET+data_length]).hexdigest(),
            copied_from_signed_image_not_live_ram=True),
        sources=sources, original_flow=emulate(image,sources),
        conclusions=dict(original_constructor_array_selectors=[10,1,2,4],
            class10_record_in_this_constructor=True, class10_selected_in_bounded_fragment=True,
            physical_class10_active='UNMEASURED', original_class10_callback='0x600613fd'),
        limits=['Initialized RAM source is OEM image data; complete startup and physical RAM are not executed/measured.',
                'R0/global base and stack are fixture inputs, matching the pinned caller argument from phase63.',
                'One fill helper is modeled; subobject initialization, mutex initialization and metadata copy helpers are no-op stubs.',
                'The four actual producer methods, record loads/copies and selector comparisons execute original code.',
                'Singleton/engine handoff is injected; full class-engine setup, its success conditions and class initializers do not execute.',
                'Inclusion of internal class10 does not imply a USB interface with bInterfaceClass 0x0A.',
                'No physical host-to-class10 callback proof, host-chosen pointer, custom execution or HAB bypass.',
                'No device I/O, mode changes, flash/eFuse writes or full firmware publication.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path)
    p.add_argument('--out',type=Path)
    args = p.parse_args()
    text = json.dumps(audit(args.image.read_bytes()),indent=2)+'\n'
    if args.out:
        args.out.write_text(text,encoding='utf-8')
    else:
        print(text,end='')


if __name__ == '__main__':
    main()
