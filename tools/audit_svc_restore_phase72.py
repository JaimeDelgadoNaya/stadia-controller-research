"""Original SVC wrapper/software restore, stopping before exception return.

Handler entry is explicit: SVC and real exception entry/unstacking do not run.
The accepted phase71 virtual machine is retained rather than resetting its CPU.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_port_start_phase71 import verify_pins as verify_port,start_case
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import constructor_case,CONTROL
from tools.audit_pending_workqueue_phase67 import queue_case,QUEUE
from tools.audit_usb_provider_phase63 import BASE

HANDLER=0x6004CB40
RETURN=0x6004CB5A


def verify_pins(image):
    verify_port(image)
    if struct.unpack_from('<I',image,0x2C)[0]!=0x6004063D:
        raise ValueError('Phase72 SVC vector drift')
    if struct.unpack_from('<I',image,0x6004CB60-BASE)[0]!=0x20027410:
        raise ValueError('Phase72 current-task literal drift')
    if struct.unpack_from('<H',image,RETURN-BASE)[0]!=0x4770:
        raise ValueError('Phase72 exact exception-return encoding drift')
    rows={i['pc']:(i['m'],i['op']) for i in decode(image,HANDLER,RETURN+2)}
    expected={HANDLER:('ldr','r3, [pc, #0x1c]'),0x6004CB42:('ldr','r1, [r3]'),
              0x6004CB44:('ldr','r0, [r1]'),RETURN:('bx','lr')}
    for pc,value in expected.items():
        if rows.get(pc)!=value:
            raise ValueError(f'Phase72 restore semantic drift at {pc:#x}')


def restore(image,uc):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_BASEPRI,UC_ARM_REG_MSP,UC_ARM_REG_PSP,UC_ARM_REG_LR,UC_ARM_REG_R0,
        UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
        UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
    )
    word=lambda address:struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    current=word(0x20027410)
    frame=word(current)
    if current!=CONTROL or frame!=0x20020B04:
        raise ValueError('Original task/frame handoff differs')
    vector=word(word(0xE000ED08)+0x2C)
    before=dict(basepri=hex(uc.reg_read(UC_ARM_REG_BASEPRI)),msp=hex(uc.reg_read(UC_ARM_REG_MSP)),
                psp=hex(uc.reg_read(UC_ARM_REG_PSP)))
    steps=[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc==RETURN:
            m.emu_stop()  # BX LR / exception-return mechanism does not execute.
        elif pc not in (0x6004063C,0x6004063E) and not HANDLER<=pc<RETURN:
            raise ValueError(f'Unexpected SVC restore execution {pc:#x}')

    handle=uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(vector,0x10000002,count=40)  # manual entry, NOT NVIC exception delivery.
    uc.hook_del(handle)
    if not steps or steps[-1]!=RETURN:
        raise ValueError('Original restore did not reach exception-return boundary')
    psp=uc.reg_read(UC_ARM_REG_PSP)
    registers=(UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
               UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11)
    actual=[uc.reg_read(r) for r in registers]
    expected=list(struct.unpack('<8I',bytes(uc.mem_read(frame,32))))
    if actual!=expected or psp!=frame+36 or uc.reg_read(UC_ARM_REG_LR)!=0xFFFFFFFD:
        raise ValueError('Original register/PSP restoration differs')
    if uc.reg_read(UC_ARM_REG_BASEPRI)!=0 or uc.reg_read(UC_ARM_REG_MSP)!=int(before['msp'],16):
        raise ValueError('Original mask-clear/MSP boundary differs')
    if (word(psp),word(psp+24),word(psp+28))!=(QUEUE,0x60101760,0x01000000):
        raise ValueError('Pending hardware frame differs')
    return dict(vector_word=hex(vector),manual_handler_entry=True,current_task=hex(current),frame_pointer=hex(frame),
        before=before,stop_pc=hex(RETURN),after=dict(basepri=hex(uc.reg_read(UC_ARM_REG_BASEPRI)),
            msp=hex(uc.reg_read(UC_ARM_REG_MSP)),psp=hex(psp),lr=hex(uc.reg_read(UC_ARM_REG_LR)),
            cpu_r0=hex(uc.reg_read(UC_ARM_REG_R0))),
        restored_r4_through_r11=[hex(v) for v in actual],restored_words_match_original_frame=True,
        pending_hardware_frame=dict(stacked_r0=hex(word(psp)),stacked_pc=hex(word(psp+24)),stacked_status=hex(word(psp+28))),
        executed_instruction_addresses=[hex(v) for v in steps[:-1]],
        svc_executed=False,exception_entry_executed=False,exception_return_executed=False,task_entry_executed=False)


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase72 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    _,initialized=constructor_case(image,ram)
    _,registered=queue_case(image,initialized,name='original_sentinel_registration',preserve_queue=True,
        execute_creator=True,execute_registration=True)
    port,uc=start_case(image,registered,0xF0,return_machine=True)
    result=restore(image,uc)
    return dict(phase=72,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        retained_pre_svc_state=port,original_software_restore=result,
        limits=['The same virtual machine is retained from the accepted phase71 port model, including CPU mask/MSP state.',
                'Handler entry follows the virtual vector manually; SVC execution, real exception entry/stacking and NVIC delivery are omitted.',
                'Original wrapper and software-restore instructions execute; BX LR is stopped before the exception-return mechanism.',
                'Pending stacked R0/PC are not yet loaded as task CPU state; no task entry or work processing executes.',
                'Priority readback, system/timer memory and prior constructor/synchronization models remain synthetic.',
                'Clearing virtual BASEPRI does not establish physical interrupt state or complete scheduler startup.',
                'No physical task/class10 activation, device commands, firmware/eFuse writes, custom code or HAB bypass.'])


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
