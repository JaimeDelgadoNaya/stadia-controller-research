"""Original port-start normalization and bounded stop before SVC.

Priority readback is an explicit byte-mask model, not real NVIC behavior.
The SVC instruction and exception/context switch do not execute.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_scheduler_registration_phase70 import verify_pins as verify_registration
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import constructor_case
from tools.audit_pending_workqueue_phase67 import queue_case
from tools.audit_usb_driver_phase66 import machine
from tools.audit_usb_provider_phase63 import BASE

ENTRY=0x600CC5AC
PROBE=0xE000E400
NESTING=0x20003D68
CLOCK=0x20003020
PINS={
    (ENTRY,0x600CC680):{
        0x600CC5BC:('strb','r2, [r3]'),
        0x600CC5BE:('ldrb','r3, [r3]'),
        0x600CC5E8:('cmp','r3, #3'),
        0x600CC5F4:('bl','#0x601016a2'),
        0x600CC608:('ldr','r4, [pc, #0x88]'),
        0x600CC620:('bl','#0x600cc578'),
        0x600CC624:('str','r5, [r4]'),
        0x600CC634:('bl','#0x600cc518'),
    },
    (0x600CC518,0x600CC53A):{
        0x600CC518:('ldr','r0, [pc, #0x20]'),
        0x600CC51E:('msr','msp, r0'),
        0x600CC526:('msr','control, r0'),
        0x600CC536:('svc','#0'),
    },
    (0x6004063C,0x60040640):{
        0x6004063C:('ldr','r0, [pc, #0x104]'),
        0x6004063E:('bx','r0'),
    },
    (0x6004CB40,0x6004CB5C):{
        0x6004CB46:('ldm.w','r0!, {r4, r5, r6, r7, r8, sb, sl, fp, lr}'),
        0x6004CB4A:('msr','psp, r0'),
        0x6004CB52:('mov.w','r0, #0'),
        0x6004CB56:('msr','basepri, r0'),
        0x6004CB5A:('bx','lr'),
    },
}


def verify_pins(image):
    verify_registration(image)
    for (lo,hi),pins in PINS.items():
        rows={i['pc']:(i['m'],i['op']) for i in decode(image,lo,hi)}
        for pc,expected in pins.items():
            if rows.get(pc)!=expected:
                raise ValueError(f'Phase71 semantic drift at {pc:#x}')
    for address,value in ((0x600CC680,PROBE),(0x600CC694,NESTING),(0x600CC53C,0xE000ED08),
                          (0x60040744,0x6004CB41)):
        if struct.unpack_from('<I',image,address-BASE)[0]!=value:
            raise ValueError('Phase71 port literal drift')


def start_case(image,ram,mask):
    from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_R1,UC_ARM_REG_BASEPRI,UC_ARM_REG_MSP
    uc=machine(image,ram)
    uc.mem_map(0xE000E000,0x1000)
    uc.mem_write(PROBE,b'\xa0')
    uc.mem_write(0xE000ED08,struct.pack('<I',BASE))  # explicit virtual VTOR fixture.
    uc.reg_write(UC_ARM_REG_BASEPRI,0x50)  # carry phase70 sentinel case's virtual mask.
    reads,writes,steps,outcome=[],[],[],[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc==0x601016A2:
            outcome.append('assertion_call_before_normalization')
            m.emu_stop()
        elif pc==0x600CC536:
            outcome.append('stopped_before_svc')
            m.emu_stop()
        elif not (ENTRY<=pc<0x600CC680 or 0x600CC578<=pc<0x600CC59A or
                  0x600CC540<=pc<0x600CC54E or 0x600CC518<=pc<0x600CC53A):
            raise ValueError(f'Unexpected port-start execution {pc:#x}')

    def read_hook(m,access,address,size,value,user):
        if address==PROBE and size==1:
            raw=bytes(m.mem_read(PROBE,1))[0]
            modeled=raw&mask
            m.mem_write(PROBE,bytes([modeled]))
            reads.append(dict(pc=hex(m.reg_read(UC_ARM_REG_PC)),stored=hex(raw),returned=hex(modeled)))

    def write_hook(m,access,address,size,value,user):
        if address==NESTING or 0xE000E000<=address<0xE000F000:
            writes.append(dict(pc=hex(m.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=hex(value)))

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_READ,read_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    uc.emu_start(ENTRY|1,0x10000002,count=1000)
    if not outcome:
        raise ValueError('Port start did not reach bounded stop')
    word=lambda address:struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    success=mask==0xF0
    if success:
        if outcome[0]!='stopped_before_svc' or word(NESTING)!=0 or uc.reg_read(UC_ARM_REG_MSP)!=struct.unpack_from('<I',image,0)[0]:
            raise ValueError('Original normalization/SVC boundary differs')
        if word(0xE000E014)!=word(CLOCK)//1000-1:
            raise ValueError('Original tick arithmetic differs')
    elif outcome[0]!='assertion_call_before_normalization' or word(NESTING)!=0xAAAAAAAA:
        raise ValueError('Priority-readback rejection differs')
    return dict(priority_readback_mask=hex(mask),initial_priority_byte='0xa0',initial_basepri='0x50',
        outcome=outcome[0],stop_pc=hex(steps[-1]),assertion_line=uc.reg_read(UC_ARM_REG_R1) if not success else None,
        nesting_after=hex(word(NESTING)),virtual_basepri_after=hex(uc.reg_read(UC_ARM_REG_BASEPRI)),
        clock_word_from_virtual_initialized_data=word(CLOCK),tick_reload=word(0xE000E014),
        virtual_vtor=hex(BASE),virtual_msp=hex(uc.reg_read(UC_ARM_REG_MSP)),
        probe_reads=reads,observed_original_writes=writes,svc_executed=False,
        task_entry_executed=0x60101760 in steps,instruction_hooks=len(steps))


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase71 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    _,initialized=constructor_case(image,ram)
    worker,registered=queue_case(image,initialized,name='original_sentinel_registration',preserve_queue=True,
        execute_creator=True,execute_registration=True)
    if worker['original_registration']['virtual_basepri']!='0x50':
        raise ValueError('Prior sentinel mask differs')
    cases=[start_case(image,registered,mask) for mask in (0xFF,0xF0,0xE0)]
    return dict(phase=71,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        original_port_entry=hex(ENTRY),normalizing_store='0x600cc624',nesting_address=hex(NESTING),
        prior_registration=worker['original_registration'],port_start_cases=cases,
        original_vector=dict(initial_msp=hex(struct.unpack_from('<I',image,0)[0]),
            svc_vector_word=hex(struct.unpack_from('<I',image,0x2C)[0]),
            wrapper_literal='0x60040744',handler_thumb='0x6004cb41',
            static_mask_clear_pc='0x6004cb56',handler_executed=False),
        limits=['Port-start entry and virtual VTOR are explicit stage fixtures; full high-level scheduler startup is not executed.',
                'Priority readback masks are synthetic byte models, not measured implemented priority bits.',
                'System/timer registers are virtual memory without actual NVIC, tick, interrupts or timing.',
                'Clock word comes from the OEM-initialized virtual snapshot, not a current physical clock measurement.',
                'Original port instructions clear the nesting word in the accepted model; BASEPRI remains 0x50 at the pre-SVC stop.',
                'SVC instruction, exception entry/return, first-task restoration and task entry do not execute.',
                'Constructor/caller/synchronization models from earlier phases remain; no physical activation or complete startup is proven.',
                'No device commands, firmware/eFuse changes, custom on-controller execution or HAB bypass.'])


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
