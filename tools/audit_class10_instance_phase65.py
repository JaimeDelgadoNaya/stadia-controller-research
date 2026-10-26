"""Original class10 instance gates and owner-to-instance flow, offline only.

Hardware-driver success/failure and guard helpers are explicit models. No
physical USB, installed RAM, actual driver execution or callback execution.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_class_records_phase64 import verify_sources, emulate as build_records
from tools.audit_usb_provider_phase63 import BASE, OWNER, RECORDS

CORE, CLASS10, ENGINE = 0x20004080, 0x200040E0, 0x200063C0
INSTANCE_OUT = RECORDS+4
PINS = {
    (0x60055024,0x60055056): {
        0x60055032: ('ldr','r2, [pc, #0x24]'),
        0x60055038: ('ldr','r3, [r2]'),
        0x6005503A: ('cbz','r3, #0x6005504e'),
        0x6005503C: ('ldrb','r2, [r2, #0xe]'),
        0x6005503E: ('cmp','r2, r5'),
        0x60055040: ('bne','#0x6005504e'),
        0x60055042: ('str','r3, [r4]'),
        0x60055048: ('movs','r0, #0'),
        0x60055052: ('movs','r0, #4'),
    },
    (0x60055320,0x6005534C): {
        0x60055322: ('ldr','r4, [pc, #0x28]'),
        0x60055328: ('ldr','r3, [r4]'),
        0x6005532A: ('cbnz','r3, #0x60055344'),
        0x6005532E: ('bl','#0x60055024'),
        0x60055332: ('cbnz','r0, #0x60055342'),
        0x6005533A: ('str','r6, [r4, #4]'),
        0x6005533C: ('strb','r0, [r4, #0xc]'),
        0x6005533E: ('strb','r3, [r4, #0xe]'),
        0x60055340: ('str','r4, [r5]'),
        0x60055344: ('movs','r0, #2'),
    },
    (0x600550E4,0x60055146): {
        0x60055126: ('strb','r6, [r3, #0xe]'),
        0x6005512E: ('str','r4, [r5, #4]'),
        0x60055138: ('bl','#0x60055350'),
        0x6005513E: ('cbnz','r0, #0x60055162'),
    },
    (0x600553BA,0x600553F4): {
        0x600553C2: ('str','r4, [r7]'),
        0x600553CA: ('blx','r3'),
        0x600553CC: ('mov','r5, r0'),
        0x600553CE: ('cbz','r0, #0x600553ec'),
    },
    (0x60060F84,0x60060F96): {
        0x60060F86: ('add.w','r2, r0, #0x98'),
        0x60060F8A: ('adds','r1, r0, #4'),
        0x60060F8E: ('ldrb','r0, [r0, #0x10]'),
        0x60060F90: ('bl','#0x600550e4'),
    },
}
LITERALS = {0x60055058:CORE, 0x6005534C:CLASS10,
            0x600553F8:ENGINE, 0x60104BC4:0x6005556D}


def verify_pins(image):
    for (start,end), expected in PINS.items():
        actual = {i['pc']:(i['m'],i['op']) for i in decode(image,start,end)}
        for pc, value in expected.items():
            if actual.get(pc) != value:
                raise ValueError(f'Phase65 semantic drift at {pc:#x}')
    for address,value in LITERALS.items():
        if struct.unpack_from('<I',image,address-BASE)[0] != value:
            raise ValueError(f'Phase65 literal drift at {address:#x}')


def virtual_case(image, ram, *, root, engine_present=False, engine_mode=2,
                 class_busy=False, driver_status=0, execute_driver=False,
                 mmio_word=8, start_transition=False):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R5,
        UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    )
    if root not in ('class','owner'):
        raise ValueError('Unknown virtual root')
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(BASE,0x110000)
    uc.mem_write(BASE,image)
    uc.mem_map(0x20000000,0x30000)
    uc.mem_write(0x20000000,ram)
    uc.mem_map(0x10000000,0x1000)
    if execute_driver:
        uc.mem_map(0x402E0000,0x1000)
        uc.mem_write(0x402E0124,struct.pack('<I',mmio_word))
    # Explicit test vectors, NOT original startup values or live measurements.
    # Also removes phase64's injected singleton/configuration handoff.
    uc.mem_write(CORE,bytes(16))
    uc.mem_write(CLASS10,bytes(16))
    uc.mem_write(ENGINE,bytes(0x100))
    uc.mem_write(INSTANCE_OUT,bytes(4))
    if engine_present:
        uc.mem_write(CORE,struct.pack('<I',ENGINE))
    if root == 'class':
        uc.mem_write(CORE+0xE,bytes([engine_mode]))
    if class_busy:
        uc.mem_write(CLASS10,struct.pack('<I',ENGINE))
    uc.reg_write(UC_ARM_REG_SP,0x2002E000)
    uc.reg_write(UC_ARM_REG_LR,0x10000001)
    if root == 'class':
        uc.reg_write(UC_ARM_REG_R0,2)
        uc.reg_write(UC_ARM_REG_R1,RECORDS)
        uc.reg_write(UC_ARM_REG_R2,INSTANCE_OUT)
        entry = 0x60055320
    else:
        uc.reg_write(UC_ARM_REG_R0,OWNER)
        entry = 0x60060FE8 if start_transition else 0x60060F84
        if start_transition:
            uc.reg_write(UC_ARM_REG_R1,2)
    steps, calls, writes = [], [], []
    outcome = []

    def hook(machine,pc,size,user):
        steps.append(pc)
        if pc == 0x10000000:
            outcome.append('class_return' if root=='class' else 'transition_early_return')
            machine.emu_stop()
            return
        if root == 'owner' and pc == 0x60055196 and 0x60055320 in steps:
            outcome.append('first_class_return_before_remaining_classes')
            machine.emu_stop()
            return
        if root == 'owner' and pc == 0x600553D0:
            outcome.append('driver_failure_before_cleanup')
            machine.emu_stop()
            return
        if (pc in (0x6013D3E0,0x600D15E8,0x6005556C) and not (execute_driver and pc==0x6005556C)) or (start_transition and pc==0x60060C70):
            call = dict(target=hex(pc),r0=hex(machine.reg_read(UC_ARM_REG_R0)))
            if pc == 0x6013D3E0:
                address = machine.reg_read(UC_ARM_REG_R0)
                if not 0x2002D000 <= address < 0x2002F000:
                    raise ValueError('Guard helper output outside virtual stack')
                machine.mem_write(address,b'\0')
                call['model']='writes zero to virtual stack status byte'
            elif pc in (0x600D15E8,0x60060C70):
                call['model']='no-op transition helper; real effects not modeled' if pc==0x60060C70 else 'no-op guard restore'
            else:
                machine.reg_write(UC_ARM_REG_R0,driver_status)
                call.update(model='stubbed low-level USB driver return; no hardware effects',returned=driver_status)
            calls.append(call)
            machine.reg_write(UC_ARM_REG_PC,machine.reg_read(UC_ARM_REG_LR))
            return
        allowed = (0x60055024 <= pc < 0x60055056 or 0x60055320 <= pc < 0x6005534C)
        if root == 'owner':
            allowed |= (0x60060F84 <= pc < 0x60060FAA or 0x600550E4 <= pc < 0x600551A6 or
                        0x60055350 <= pc < 0x600553F8)
            if execute_driver:
                allowed |= (0x6005556C <= pc < 0x600555C4 or 0x60055400 <= pc < 0x600554A0)
            if start_transition:
                allowed |= 0x60060FE8 <= pc < 0x600610B8
        if not allowed:
            raise ValueError(f'Unexpected phase65 execution {pc:#x}')

    fields = {CORE,CORE+4,CORE+0xE,CLASS10,CLASS10+4,CLASS10+0xC,CLASS10+0xE,INSTANCE_OUT}

    def on_write(machine,access,address,size,value,user):
        if address in fields or (execute_driver and 0x402E0000 <= address < 0x402E1000):
            writes.append(dict(pc=hex(machine.reg_read(UC_ARM_REG_PC)),
                address=hex(address),size=size,value=hex(value)))

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,on_write)
    uc.emu_start(entry|1,0x10000002,count=1500)
    if not outcome:
        raise ValueError('Phase65 virtual case did not reach a bounded stop')
    word = lambda address: struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    result=dict(root=root,inputs=dict(engine_present=engine_present,engine_mode=engine_mode,
            class_busy=class_busy,requested_class_mode=2,driver_status_stub=driver_status),
        stop=outcome[0],stop_pc=hex(steps[-1]),r0_at_stop=uc.reg_read(UC_ARM_REG_R0),
        driver_error_r5_at_failure=uc.reg_read(UC_ARM_REG_R5) if outcome[0]=='driver_failure_before_cleanup' else None,
        class10_initializer_reached=0x60055320 in steps,
        snapshot=dict(core_engine=hex(word(CORE)),core_config=hex(word(CORE+4)),
            class_engine=hex(word(CLASS10)),class_record=hex(word(CLASS10+4)),
            class_status_byte=bytes(uc.mem_read(CLASS10+0xC,1))[0],
            class_marker_byte=bytes(uc.mem_read(CLASS10+0xE,1))[0],
            record_instance=hex(word(INSTANCE_OUT))),
        original_writes=writes,stubbed_calls=calls,instruction_hooks=len(steps))
    if execute_driver:
        result['inputs']['driver_status_stub']=None
        result['original_driver']=dict(executed=True,mmio_model='plain virtual memory; no register side effects',
            hardware_word=hex(mmio_word),low_five_bits=mmio_word&31,
            engine_driver_object=hex(word(ENGINE)),driver_context=hex(word(0x20011DFC)))
    if start_transition:
        result['transition']=dict(executed=True,prior_mode_input=struct.unpack_from('<I',ram,OWNER+0x90-0x20000000)[0],
            mode_at_stop=word(OWNER+0x90),requested_mode=2,
            note='0x60060c70 is a no-op; stop precedes final mode publication')
    return result


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase65 exact SHA-pinned original OEM image required')
    verify_pins(image)
    sources=verify_sources(image)
    _,ram=build_records(image,sources,return_ram=True)
    profiles=(('no_engine',False,2,False),('wrong_mode',True,3,False),
              ('matching_engine',True,2,False),('class_busy',True,2,True),
              ('class_busy_without_engine',False,2,True))
    cases=[]
    for name,present,mode,busy in profiles:
        result=virtual_case(image,ram,root='class',engine_present=present,engine_mode=mode,class_busy=busy)
        result['name']=name
        expected=2 if busy else 0 if present and mode==2 else 4
        if result['r0_at_stop']!=expected:
            raise ValueError('Original class10 gate outcome differs')
        if expected==0:
            if (result['snapshot']['record_instance'],result['snapshot']['class_record'])!=(hex(CLASS10),hex(RECORDS)):
                raise ValueError('Original class10 instance binding missing')
        elif result['snapshot']['record_instance']!='0x0':
            raise ValueError('Rejected class10 case unexpectedly published an instance')
        cases.append(result)
    chains=[]
    for status in (0,5):
        result=virtual_case(image,ram,root='owner',driver_status=status)
        if status==0:
            s=result['snapshot']
            if result['r0_at_stop']!=0 or (s['core_config'],s['class_engine'],s['class_record'],s['record_instance'])!=(hex(OWNER+4),hex(ENGINE),hex(RECORDS),hex(CLASS10)):
                raise ValueError('Owner-to-class10 original binding failed')
            if s['class_status_byte']!=0 or s['class_marker_byte']!=255:
                raise ValueError('Class10 original metadata bytes differ')
        elif result['class10_initializer_reached'] or result['stop']!='driver_failure_before_cleanup' or result['driver_error_r5_at_failure']!=status:
            raise ValueError('Driver failure did not block the class10 path')
        chains.append(result)
    previous=struct.unpack_from('<I',ram,OWNER+0x90-0x20000000)[0]
    return dict(phase=65,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        source_array_selectors=[s['selector'] for s in sources],class_state=hex(CLASS10),
        isolated_class10_cases=cases,owner_to_class10_cases=chains,
        constructor_snapshot_previous_mode=previous,
        mode_transition_boundary='Phase53 requires prior mode nonzero and different from requested 2; owner root bypasses that transition.',
        limits=['Original instructions execute only in virtual fragments with explicit test vectors.',
                'The original-record RAM snapshot inherits the phase64 subobject/mutex/copy-helper models.',
                'Core/class/engine state is reset or seeded as test vectors; these are not measured installed values.',
                'Owner path executes the original singleton/configuration writes; phase64 singleton handoff is removed first.',
                'Low-level driver 0x6005556c returns an injected status; no actual USB engine or peripherals are initialized.',
                'Guard helpers are explicit status-byte/no-op models; their real implementation and concurrent effects are not executed.',
                'Success stops after the first class initializer, before other classes and final owner registration/return.',
                'Failure stops before cleanup; transient pointer values do not establish final cleanup state.',
                'Mode-transition guards and actual runtime state remain outside this experiment.',
                'No class callback executes; no physical USB reachability, custom code execution, HAB bypass or firmware modification.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    result=json.dumps(audit(args.image.read_bytes()),indent=2)+'\n'
    if args.out:
        args.out.write_text(result,encoding='utf-8')
    else:
        print(result,end='')


if __name__=='__main__':
    main()
