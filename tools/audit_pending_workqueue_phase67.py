"""Resolve the pending mode-1 call using original code and explicit queue models.

No physical device or scheduler executes. Label/field behavior is recorded;
opaque nonzero fields do not prove a valid or running task.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_usb_driver_phase66 import verify_pins as verify_previous, machine
from tools.audit_class10_instance_phase65 import virtual_case
from tools.audit_usb_provider_phase63 import BASE,GLOBAL,OWNER

QUEUE=0x2002014C
CONTROL=0x20024000
OPAQUE=0x20025000
LABEL=0x6012F592
PINS={
    (0x6009267C,0x60092698):{
        0x6009267C:('mov','r2, r0'),
        0x6009267E:('ldr','r0, [pc, #0x18]'),
        0x60092682:('ldr','r1, [r0, #0x58]'),
        0x60092684:('cbnz','r1, #0x60092692'),
        0x60092688:('bl','#0x6010177a'),
        0x60092692:('mov.w','r0, #0'),
    },
    (0x6010177A,0x6010179A):{
        0x60101782:('bl','#0x6013d2d0'),
        0x6010178C:('bl','#0x600cc178'),
        0x60101792:('bl','#0x6013d0e0'),
    },
    (0x600CC178,0x600CC1BA):{
        0x600CC17E:('ldr','r4, [r5, #0x58]'),
        0x600CC18A:('ldr','r3, [r5, #0x5c]'),
        0x600CC18C:('cbz','r3, #0x600cc1b2'),
        0x600CC18E:('ldr.w','r2, [r3, #0xd0]'),
        0x600CC192:('lsls','r6, r2, #2'),
        0x600CC194:('cmp.w','r6, #0x800'),
        0x600CC198:('blo','#0x600cc1b6'),
        0x600CC1A8:('bl','#0x600ca1f8'),
        0x600CC1AC:('str','r0, [r5, #0x58]'),
        0x600CC1AE:('mov','r0, r4'),
        0x600CC1B2:('movs','r0, #9'),
        0x600CC1B6:('movs','r0, #3'),
    },
    (0x60060F34,0x60060F3E):{
        0x60060F34:('bl','#0x6009267c'),
        0x60060F38:('tst.w','r0, #0xff'),
        0x60060F3C:('beq','#0x60060f74'),
    },
}


def verify_pins(image):
    verify_previous(image)
    for (start,end),pins in PINS.items():
        rows={i['pc']:(i['m'],i['op']) for i in decode(image,start,end)}
        for pc,expected in pins.items():
            if rows.get(pc)!=expected:
                raise ValueError(f'Phase67 semantic drift at {pc:#x}')
    for address,value in ((0x60092698,QUEUE),(0x6009269C,LABEL)):
        if struct.unpack_from('<I',image,address-BASE)[0]!=value:
            raise ValueError('Phase67 queue literal drift')
    if image[LABEL-BASE:LABEL-BASE+16]!=b'Work Queue Task\0':
        raise ValueError('Phase67 original label drift')


def queue_case(image,ram,*,name,existing=False,control=False,words=0x200,preserve_queue=False):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_PC,UC_ARM_REG_LR
    uc=machine(image,ram)
    if preserve_queue:
        handle,auxiliary=struct.unpack('<II',bytes(uc.mem_read(QUEUE+0x58,8)))
        existing,control=bool(handle),bool(auxiliary)
        words=struct.unpack('<I',bytes(uc.mem_read(auxiliary+0xD0,4)))[0] if control else 0
    else:
        uc.mem_write(QUEUE+0x58,struct.pack('<II',OPAQUE if existing else 0,CONTROL if control else 0))
        if control:
            uc.mem_write(CONTROL+0xCC,struct.pack('<II',1,words))
    uc.reg_write(UC_ARM_REG_R5,GLOBAL)
    uc.reg_write(UC_ARM_REG_R6,0x2002E010)
    steps,calls=[],[]
    status=[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc in (0x600747B6,0x60060F3E):
            status.append('mode_function_returned_to_caller' if pc==0x600747B6 else 'mode_function_error_branch_before_logging')
            m.emu_stop()
            return
        if pc in (0x6006581C,0x60071580,0x600D5494,0x600D54A6,0x6013D2D0,0x6013D0E0,0x600CA1F8):
            values=[m.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
            calls.append(dict(target=hex(pc),arguments=[hex(v) for v in values],
                model='opaque modeled creation return; scheduler not executed' if pc==0x600CA1F8 else 'no-op returning zero'))
            m.reg_write(UC_ARM_REG_R0,OPAQUE if pc==0x600CA1F8 else 0)
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
            return
        allowed=(0x60074772<=pc<0x600747B6 or 0x60060F28<=pc<0x60060F7A or
                 0x6009267C<=pc<0x60092698 or 0x6010177A<=pc<0x6010179A or
                 0x600CC178<=pc<0x600CC1BA)
        if not allowed:
            raise ValueError(f'Unexpected pending-call execution {pc:#x}')

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(0x60074773,0x10000002,count=600)
    if not status or 0x6009267C not in steps:
        raise ValueError('Pending original call was not executed')
    mode=struct.unpack('<I',bytes(uc.mem_read(OWNER+0x90,4)))[0]
    expected=0 if existing or control and ((words<<2)&0xFFFFFFFF)>=0x800 else 3 if control else 9
    if mode!=1 or (status[0]=='mode_function_returned_to_caller')!=(expected==0):
        raise ValueError('Original pending-call case outcome differs')
    if uc.reg_read(UC_ARM_REG_R0)!=expected:
        raise ValueError('Original pending-call error status differs')
    result=dict(name=name,inputs=dict(nonzero_handle_field=existing,control_pointer_present=control,control_words=words if control else None),
        outcome=status[0],stop_pc=hex(steps[-1]),original_queue_status=expected,mode_field_after_attempt=mode,
        handle_field_after=hex(struct.unpack('<I',bytes(uc.mem_read(QUEUE+0x58,4)))[0]),
        original_pending_call_executed=True,creation_primitive_reached=0x600CA1F8 in steps,
        creator_r0_literal=hex(struct.unpack_from('<I',image,0x600CC1BC-BASE)[0]) if 0x600CA1F8 in steps else None,
        models=calls,instruction_hooks=len(steps))
    if preserve_queue:
        result['queue_fields_preserved_from_input']=True
        result['initial_control_pointer']=hex(auxiliary)
    return result,bytes(uc.mem_read(0x20000000,0x30000))


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase67 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    profiles=(dict(name='nonzero_handle_field',existing=True),dict(name='empty_without_control'),
              dict(name='control_below_threshold',control=True,words=0x1FF),
              dict(name='control_at_threshold_modeled_creation',control=True,words=0x200))
    cases=[]
    ready=None
    for profile in profiles:
        result,state=queue_case(image,ram,**profile)
        cases.append(result)
        if profile['name']=='nonzero_handle_field':
            ready=state
            if result['creation_primitive_reached'] or any(c['target'] in ('0x6013d2d0','0x6013d0e0') for c in result['models']):
                raise ValueError('Nonzero-handle fast path unexpectedly used creation/wrapper stubs')
    chain=virtual_case(image,ready,root='owner',execute_driver=True,mmio_word=8,start_transition=True)
    if chain['snapshot']['record_instance']!='0x200040e0':
        raise ValueError('Post-return transition chain did not bind class10')
    return dict(phase=67,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        queue_object=hex(QUEUE),handle_field=hex(QUEUE+0x58),control_field=hex(QUEUE+0x5C),
        original_label='Work Queue Task',label_literal=hex(LABEL),
        label_interpretation='OEM label and creation-shaped code; valid/running scheduler task is not proven',
        cases=cases,post_completed_mode_function_chain=chain,
        limits=['All RAM/state inputs are virtual; queue fields are fixtures, not installed values.',
                'Nonzero handle field is not validated as a real, valid or running task by the fast path.',
                'Creation path models 0x600ca1f8 and synchronization hooks; real allocation/scheduler behavior is not executed.',
                'Four activation-caller registration helpers retain no-op models and fragment inputs remain synthetic.',
                'Pending 0x6009267c executes through original return or observed error branch; it is no longer omitted.',
                'Composition starts the transition as a new stage only after a normal original mode-function return.',
                'Remaining transition/constructor guard models and virtual MMIO semantics are inherited from phases64-66.',
                'Class10 binding remains a conditional virtual result; final mode publication, callbacks and physical USB remain unmeasured.',
                'No physical commands, firmware/eFuse changes, custom device execution or HAB bypass.'])


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
