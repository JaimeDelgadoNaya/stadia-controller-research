"""Phase 74: signed original queue-receive entry and bounded ITCM inspection.

No physical USB, no flash writes, no unknown work item injected.
The phase73 task execution stops before BL 0x6013D268; this phase
identifies the call's original instructions and the signed target/veneer,
and inspects the actual prepared queue control in the same virtual state.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256
from tools.audit_usb_provider_phase63 import BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET,ITCM_LENGTH
from tools.audit_task_entry_phase73 import verify_pins as verify_previous,enter_task,WAIT
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import constructor_case
from tools.audit_pending_workqueue_phase67 import queue_case,QUEUE
from tools.audit_port_start_phase71 import start_case
from tools.audit_svc_restore_phase72 import restore
from tools.audit_bruce_ep0_registration import decode
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS

VENEER=0x6013D268
QUEUE_CONTROL_OFFSET=0xB0
OUTPUT_DEFAULT=0

def word(image,addr):
    if addr%4 or not BASE<=addr<=BASE+len(image)-4:
        raise ValueError('Invalid original signed word access')
    return struct.unpack_from('<I',image,addr-BASE)[0]

def code_window(image,address,end):
    if not BASE<=address<end<=BASE+len(image):
        raise ValueError('Outside mapped signed XIP window')
    return [{'pc':hex(r['pc']),'m':r['m'],'op':r['op']}
            for r in decode(image,address,end)]

def itcm_code(image,pc,length):
    if pc%2 or pc<0 or pc+length>ITCM_LENGTH:
        raise ValueError('Outside signed original ITCM copy')
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    data=image[ITCM_SOURCE_OFFSET+pc:ITCM_SOURCE_OFFSET+pc+length]
    return [{'pc':hex(i.address),'m':i.mnemonic,'op':i.op_str}
            for i in cs.disasm(data,pc)]

def receiver_code(image):
    veneer=code_window(image,VENEER,VENEER+4)
    literals=[{'pc':hex(i),'word':hex(word(image,i))}
              for i in (VENEER+4,)]
    target=word(image,VENEER+4)
    dest=target&~1
    kind=('relocated_ITCM' if target&1 and 0<=dest<ITCM_LENGTH
          else 'XIP' if target&1 and BASE<=dest<BASE+len(image)
          else 'UNKNOWN_OR_NOT_THUMB')
    ins=(itcm_code(image,dest,0x180) if kind=='relocated_ITCM'
         else code_window(image,dest,dest+0x180) if kind=='XIP' else [])
    return dict(veneer=veneer,literals=literals,raw_thumb_target=hex(target),
                target_kind=kind,target_pc=hex(dest),target_preview=ins[:95],
                target_source_offset=(hex(ITCM_SOURCE_OFFSET+dest) if kind=='relocated_ITCM'
                                      else hex(dest-BASE) if kind=='XIP' else None))

def prepare_phase73_state(image):
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    _,initialized=constructor_case(image,ram)
    _,registered=queue_case(image,initialized,name='original_sentinel_registration',
                            preserve_queue=True,execute_creator=True,execute_registration=True)
    port,uc=start_case(image,registered,0xF0,return_machine=True)
    software=restore(image,uc)
    entry=enter_task(uc)
    return uc,entry

def queue_snapshot(uc):
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_SP
    read=lambda addr:struct.unpack('<I',bytes(uc.mem_read(addr,4)))[0]
    ctrl=read(QUEUE+QUEUE_CONTROL_OFFSET)
    if uc.reg_read(UC_ARM_REG_R0)!=ctrl or uc.reg_read(UC_ARM_REG_R2)!=0xFFFFFFFF:
        raise ValueError('Original worker queue arguments have drifted')
    # Snapshot is virtual, not necessarily a live real-time queue state.
    return {
        'queue_object':hex(QUEUE),'control_field':hex(QUEUE+QUEUE_CONTROL_OFFSET),
        'control_pointer':hex(ctrl),
        'worker_wait_call':hex(WAIT),'worker_call_target':hex(VENEER),
        'queue_receive_r0':hex(uc.reg_read(UC_ARM_REG_R0)),
        'queue_receive_r1_output':hex(uc.reg_read(UC_ARM_REG_R1)),
        'queue_receive_r2_timeout':hex(uc.reg_read(UC_ARM_REG_R2)),
        'virtual_SP':hex(uc.reg_read(UC_ARM_REG_SP)),
        'control_words':[hex(read(ctrl+o)) for o in range(0,0x40,4)],
        'output_before':hex(read(uc.reg_read(UC_ARM_REG_R1))),
    }

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase74 exact SHA-pinned OEM required')
    verify_previous(image)
    entry=code_window(image,WAIT,WAIT+4)
    if len(entry)!=1 or (entry[0]['m'],entry[0]['op'])!=('bl','#0x6013d268'):
        raise ValueError('Phase74 signed first queue call drift')
    target=receiver_code(image)
    uc,t73=prepare_phase73_state(image)
    snap=queue_snapshot(uc)
    return dict(phase=74,original_signed_image_SHA256=IMAGE_SHA256,
                hash_verified=True,
                signed_receiver=target,
                inherited_phase73_target=t73['stop_before_queue_call'],
                inherited_phase73_virtual_state=snap,
                boundaries=[
                    'Only the signed receiver has been disassembled; queue call itself has NOT been executed in this exploratory audit.',
                    'Virtual Work Queue pointer/contents come from inherited modeled scheduler and constructor; no physical RAM observed.',
                    'No messages, callbacks, blocking, scheduler switching, exception return or USB packets are simulated in receiver.',
                    'No physical USB, flash write, eFuse change, custom execution or HAB CLOSED bypass.',
                ])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    r=audit(args.image.read_bytes())
    s=json.dumps(r,indent=2)+'\n'
    if args.out:args.out.write_text(s,encoding='utf-8')
    print('PHASE74 RECEIVER TARGET',json.dumps(r['signed_receiver']))
    print('PHASE74 VIRTUAL QUEUE SNAPSHOT',json.dumps(r['inherited_phase73_virtual_state']))
    print('PHASE74 UNEXECUTED RECEIVER INSPECTION')
if __name__=='__main__':
    main()
