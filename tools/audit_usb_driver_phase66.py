"""Original USB driver/MMIO gate and original prior-mode writer, offline.

MMIO is plain virtual memory with synthetic contents, not controller hardware.
The mode-writer/transition join is explicit and omits the pending external call.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_class_records_phase64 import verify_sources, emulate as build_records
from tools.audit_class10_instance_phase65 import virtual_case
from tools.audit_usb_provider_phase63 import BASE, GLOBAL, OWNER

MMIO, DRIVER, ENGINE = 0x402E0000, 0x20011DFC, 0x200063C0
PINS = {
    (0x6005556C,0x600555C4): {
        0x6005556C:('cmp','r0, #2'),
        0x60055572:('bne','#0x600555bc'),
        0x60055584:('ldr.w','r0, [r3, #0x124]'),
        0x6005558A:('and','r0, r0, #0x1f'),
        0x6005558E:('cmp','r0, #7'),
        0x60055594:('bls','#0x600555c0'),
        0x600555B2:('bl','#0x60055400'),
        0x600555B6:('movs','r0, #0'),
        0x600555B8:('str','r4, [r5]'),
        0x600555BC:('movs','r0, #6'),
        0x600555C0:('movs','r0, #1'),
    },
    (0x60074658,0x60074660): {0x6007465A:('mov','r5, r0')},
    (0x60074772,0x60074782): {
        0x60074776:('add.w','r7, r5, #0x3dc0'),
        0x6007477C:('adds','r7, #0x28'),
    },
    (0x600747B0,0x600747B6): {
        0x600747B0:('mov','r0, r7'),
        0x600747B2:('bl','#0x60060f28'),
    },
    (0x60060F28,0x60060F38): {
        0x60060F28:('movs','r3, #1'),
        0x60060F2C:('str.w','r3, [r0, #0x90]'),
        0x60060F34:('bl','#0x6009267c'),
    },
}
LITERALS={0x600555C4:DRIVER,0x600555C8:0x20002340,
          0x600555CC:0x20001000,0x600555D0:MMIO}


def verify_pins(image):
    for (start,end),pins in PINS.items():
        rows={i['pc']:(i['m'],i['op']) for i in decode(image,start,end)}
        for pc,expected in pins.items():
            if rows.get(pc)!=expected:
                raise ValueError(f'Phase66 semantic drift at {pc:#x}')
    for address,value in LITERALS.items():
        if struct.unpack_from('<I',image,address-BASE)[0]!=value:
            raise ValueError(f'Phase66 literal drift at {address:#x}')


def machine(image,ram=None):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    uc.mem_map(BASE,0x110000)
    uc.mem_write(BASE,image)
    uc.mem_map(0x20000000,0x30000)
    if ram is not None:
        uc.mem_write(0x20000000,ram)
    uc.mem_map(0x10000000,0x1000)
    uc.reg_write(UC_ARM_REG_SP,0x2002E000)
    uc.reg_write(UC_ARM_REG_LR,0x10000001)
    return uc


def driver_case(image,mode,hardware_word):
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC
    uc=machine(image)
    uc.mem_map(MMIO,0x1000)
    uc.mem_write(MMIO+0x124,struct.pack('<I',hardware_word))
    for register,value in ((UC_ARM_REG_R0,mode),(UC_ARM_REG_R1,ENGINE),(UC_ARM_REG_R2,ENGINE)):
        uc.reg_write(register,value)
    steps,reads,writes=[],[],[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc==0x10000000:
            m.emu_stop()
        elif not (0x6005556C<=pc<0x600555C4 or 0x60055400<=pc<0x600554A0):
            raise ValueError(f'Unexpected original driver execution {pc:#x}')

    def read_hook(m,access,address,size,value,user):
        if MMIO<=address<MMIO+0x1000:
            reads.append(hex(address))

    def write_hook(m,access,address,size,value,user):
        if MMIO<=address<MMIO+0x1000:
            writes.append(dict(pc=hex(m.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=hex(value)))

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_READ,read_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    uc.emu_start(0x6005556D,0x10000002,count=2000)
    if not steps or steps[-1]!=0x10000000:
        raise ValueError('Original driver did not return within bound')
    word=lambda address:struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    result=uc.reg_read(UC_ARM_REG_R0)
    expected=6 if mode!=2 else 1 if hardware_word&31<=7 else 0
    if result!=expected or (word(ENGINE)!=(DRIVER if expected==0 else 0)):
        raise ValueError('Original MMIO gate or driver output differs')
    return dict(mode=mode,synthetic_hardware_word=hex(hardware_word),masked_low_five_bits=hardware_word&31,
        original_return=result,output_driver_pointer=hex(word(ENGINE)),
        helper_55400_executed=0x60055400 in steps,
        driver_context=hex(word(DRIVER)),mmio_reads=reads,mmio_writes=writes,
        instruction_hooks=len(steps),driver_or_helper_stubbed=False)


def prior_mode_writer(image,ram):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_PC, UC_ARM_REG_LR
    uc=machine(image,ram)
    uc.reg_write(UC_ARM_REG_R5,GLOBAL)
    uc.reg_write(UC_ARM_REG_R6,0x2002E010)
    steps,calls=[],[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc==0x60060F34:
            m.emu_stop()  # before the pending external implementation.
        elif pc in (0x6006581C,0x60071580,0x600D5494,0x600D54A6):
            calls.append(dict(target=hex(pc),input_r0=hex(m.reg_read(UC_ARM_REG_R0)),model='no-op returning zero'))
            m.reg_write(UC_ARM_REG_R0,0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif not (0x60074772<=pc<0x600747B6 or 0x60060F28<=pc<0x60060F34):
            raise ValueError(f'Unexpected prior-mode fragment {pc:#x}')

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(0x60074773,0x10000002,count=200)
    mode=struct.unpack('<I',bytes(uc.mem_read(OWNER+0x90,4)))[0]
    if steps[-1]!=0x60060F34 or mode!=1:
        raise ValueError('Original prior-mode writer did not establish one')
    return dict(owner_argument=hex(OWNER),mode_field=hex(OWNER+0x90),original_store='0x60060f2c',
        value_after_store=mode,stop_before_call='0x6009267c',stubbed_calls=calls),bytes(uc.mem_read(0x20000000,0x30000))


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase66 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    raw=[driver_case(image,mode,value) for mode,value in ((2,0),(2,7),(2,8),(2,31),(2,0x108),(2,0x100),(3,8))]
    writer,ready=prior_mode_writer(image,ram)
    chains=[]
    for name,state,value in (('original_snapshot_mode_zero',ram,8),('after_original_mode_one_store',ready,8),
                             ('mode_one_but_mmio_gate_fails',ready,7)):
        result=virtual_case(image,state,root='owner',execute_driver=True,mmio_word=value,start_transition=True)
        result['name']=name
        if name=='original_snapshot_mode_zero':
            if result['stop']!='transition_early_return' or result['class10_initializer_reached']:
                raise ValueError('Mode-zero transition guard did not block')
        elif value==8:
            if result['snapshot']['record_instance']!='0x200040e0' or result['original_driver']['engine_driver_object']!=hex(DRIVER):
                raise ValueError('Original driver-to-class10 chain failed')
            if any(c['target']=='0x6005556c' for c in result['stubbed_calls']):
                raise ValueError('Driver was unexpectedly stubbed')
        elif result['class10_initializer_reached'] or result['driver_error_r5_at_failure']!=1:
            raise ValueError('Original driver failure did not gate class10')
        chains.append(result)
    return dict(phase=66,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        hardware_gate=dict(address=hex(MMIO+0x124),mask='0x1f',reject_if_masked_value_at_most=7,
                           register_name_or_hardware_meaning='NOT ASSIGNED IN THIS AUDIT'),
        raw_original_driver_cases=raw,original_prior_mode_writer=writer,transition_driver_class10_cases=chains,
        limits=['MMIO is plain virtual memory seeded by test vectors; no physical registers are read or written.',
                'Real peripheral read/write side effects, clocks, resets, DMA and timing are not modeled.',
                'Driver 0x6005556c and initializer 0x60055400 execute original code without stubs in this phase.',
                'Prior-mode caller fragment uses synthetic R5/global and R6/stack inputs; four registration helpers are no-op zero-return stubs.',
                'Prior-mode stage stops before 0x6009267c; joining that RAM to the transition omits the pending call and any effects/failures.',
                'Transition helper 0x60060c70 and state-guard helpers retain explicit models, as do phase64 constructor dependencies.',
                'Successful composition stops after the first class; final requested-mode publication and complete startup remain unexecuted.',
                'No physical class10 activation, callback execution, custom code, HAB bypass or firmware changes demonstrated.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    text=json.dumps(audit(args.image.read_bytes()),indent=2)+'\n'
    if args.out:
        args.out.write_text(text,encoding='utf-8')
    else:
        print(text,end='')


if __name__=='__main__':
    main()
