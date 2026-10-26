"""Explicit basic-frame return model, then bounded original task-entry code.

BX LR/NVIC exception return is NOT executed. The model is limited to the
observed basic thread/PSP frame; original entry stops before the first queue call.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_svc_restore_phase72 import verify_pins as verify_restore,restore
from tools.audit_port_start_phase71 import start_case
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import constructor_case
from tools.audit_pending_workqueue_phase67 import queue_case,QUEUE
from tools.audit_bruce_ep0_registration import decode

TASK=0x60101760
WORKER=0x600EE142
WAIT=0x600EE152


def basic_frame_plan(exception_return,psp,words):
    if exception_return!=0xFFFFFFFD or psp&7 or len(words)!=8:
        raise ValueError('Unsupported exception-return/frame shape')
    if not words[7]&0x01000000 or words[7]&0x200 or words[7]&0x1FF:
        raise ValueError('Unsupported frame status/alignment model')
    return dict(r0=words[0],r1=words[1],r2=words[2],r3=words[3],r12=words[4],lr=words[5],
                pc=words[6],status=words[7],psp_after=psp+32)


def verify_pins(image):
    verify_restore(image)
    pins={TASK:('push','{r4, lr}'),0x60101764:('ldr','r3, [r4], #4'),
          0x60101768:('ldr','r3, [r3, #8]'),0x6010176A:('blx','r3'),
          WORKER:('push','{r4, r5, r6, r7, lr}'),0x600EE148:('mov.w','r2, #-1'),
          0x600EE14E:('ldr.w','r0, [r7, #0xb0]'),WAIT:('bl','#0x6013d268')}
    rows={}
    for lo,hi in ((TASK,0x6010176C),(WORKER,WAIT+4)):
        rows.update({i['pc']:(i['m'],i['op']) for i in decode(image,lo,hi)})
    for pc,expected in pins.items():
        if rows.get(pc)!=expected:
            raise ValueError(f'Phase73 entry semantic drift at {pc:#x}')


def enter_task(uc):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12,
        UC_ARM_REG_LR,UC_ARM_REG_PSP,UC_ARM_REG_MSP,UC_ARM_REG_CONTROL,UC_ARM_REG_XPSR,UC_ARM_REG_SP,
    )
    word=lambda address:struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    psp=uc.reg_read(UC_ARM_REG_PSP)
    frame=list(struct.unpack('<8I',bytes(uc.mem_read(psp,32))))
    plan=basic_frame_plan(uc.reg_read(UC_ARM_REG_LR),psp,frame)
    if plan['pc']!=TASK or plan['r0']!=QUEUE:
        raise ValueError('Prepared task target/argument differs')
    before_msp=uc.reg_read(UC_ARM_REG_MSP)
    for register,key in ((UC_ARM_REG_R0,'r0'),(UC_ARM_REG_R1,'r1'),(UC_ARM_REG_R2,'r2'),
                         (UC_ARM_REG_R3,'r3'),(UC_ARM_REG_R12,'r12'),(UC_ARM_REG_LR,'lr')):
        uc.reg_write(register,plan[key])
    # Explicit software bridge, not execution of BX LR or architectural exception return.
    uc.reg_write(UC_ARM_REG_XPSR,plan['status'])
    uc.reg_write(UC_ARM_REG_PSP,plan['psp_after'])
    uc.reg_write(UC_ARM_REG_CONTROL,uc.reg_read(UC_ARM_REG_CONTROL)|2)
    if uc.reg_read(UC_ARM_REG_SP)!=plan['psp_after']:
        raise ValueError('Virtual thread-stack selection differs')
    steps=[]

    def hook(machine,pc,size,user):
        steps.append(pc)
        if pc==WAIT:
            machine.emu_stop()  # queue receive/wait call itself does not execute.
        elif not (TASK<=pc<0x6010176C or WORKER<=pc<WAIT):
            raise ValueError(f'Unexpected original task-entry instruction {pc:#x}')

    handle=uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(plan['pc']|1,0x10000002,count=100)
    uc.hook_del(handle)
    if not steps or steps[-1]!=WAIT or WORKER not in steps:
        raise ValueError('Original task entry did not reach its queue call')
    queue_control=word(QUEUE+0xB0)
    if uc.reg_read(UC_ARM_REG_R0)!=queue_control or uc.reg_read(UC_ARM_REG_R2)!=0xFFFFFFFF:
        raise ValueError('Original work-loop call arguments differ')
    if uc.reg_read(UC_ARM_REG_MSP)!=before_msp:
        raise ValueError('Task fragment unexpectedly changed MSP')
    return dict(exception_return_model=dict(type='explicit eight-word basic frame; no real exception mechanism',
            input_psp=hex(psp),loaded={k:hex(v) for k,v in plan.items()},
            selected_psp=hex(plan['psp_after']),svc_executed=False,bx_lr_executed=False),
        original_task_entry=hex(TASK),original_vtable=hex(word(QUEUE)),
        original_worker_method=hex(word(word(QUEUE)+8)),stop_before_queue_call=hex(WAIT),
        observed_call_arguments=dict(r0_queue_control=hex(uc.reg_read(UC_ARM_REG_R0)),
            r1_output_buffer=hex(uc.reg_read(UC_ARM_REG_R1)),r2_wait_value=hex(uc.reg_read(UC_ARM_REG_R2))),
        final_virtual_sp=hex(uc.reg_read(UC_ARM_REG_SP)),final_virtual_msp=hex(uc.reg_read(UC_ARM_REG_MSP)),
        original_instruction_addresses=[hex(pc) for pc in steps[:-1]],
        task_entry_executed_in_virtual_model=True,queue_call_executed=False,work_item_callback_executed=False)


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase73 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    _,initialized=constructor_case(image,ram)
    _,registered=queue_case(image,initialized,name='original_sentinel_registration',preserve_queue=True,
        execute_creator=True,execute_registration=True)
    port,uc=start_case(image,registered,0xF0,return_machine=True)
    software=restore(image,uc)
    result=enter_task(uc)
    return dict(phase=73,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        prior_port_outcome=port['outcome'],prior_software_restore=software['after'],
        task_entry_case=result,
        limits=['Exception return is an explicit register/frame model, not execution of SVC/BX LR, exception entry/return or NVIC.',
                'Only the observed basic PSP/thread frame is supported; floating/extended or alignment-padded frames are rejected.',
                'After that bridge, original task wrapper and indirect worker method execute until their first queue call.',
                'The queue call, blocking/scheduling, work-item dequeue and callback invocation do not execute.',
                'The same virtual machine is retained; constructor/synchronization and system/priority/timer models remain inherited.',
                'Virtual task-entry execution does not establish physical task/class10 activation or a USB-to-work-item path.',
                'No device commands, firmware/eFuse changes, custom on-controller code or HAB bypass.'])


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
