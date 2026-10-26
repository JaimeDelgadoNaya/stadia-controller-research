"""Original task-state preparation and handle provenance, offline only.

Creation routine and frame preparation execute original instructions. Scheduler
registration remains a stub; preparing a frame does not demonstrate execution.
"""
import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import verify_pins as verify_constructor,constructor_case,CONTROL,STACK
from tools.audit_pending_workqueue_phase67 import queue_case,QUEUE
from tools.audit_class10_instance_phase65 import virtual_case

PINS={
    (0x600CA1F8,0x600CA26C):{
        0x600CA206:('ldrd','r4, r5, [sp, #0x3c]'),
        0x600CA242:('str','r4, [r5, #0x30]'),
        0x600CA25A:('bl','#0x600ca0fc'),
        0x600CA260:('bl','#0x600c9fd8'),
        0x600CA264:('ldr','r0, [sp, #0x14]'),
    },
    (0x600CA0FC,0x600CA1A4):{
        0x600CA116:('ldr','r0, [r4, #0x30]'),
        0x600CA118:('bl','#0x6013cf90'),
        0x600CA128:('bic','sl, sl, #7'),
        0x600CA150:('str','r6, [r4, #0x2c]'),
        0x600CA198:('bl','#0x600cc554'),
        0x600CA19C:('str','r0, [r4]'),
        0x600CA1A0:('str','r4, [r7]'),
    },
    (0x600CC554,0x600CC572):{
        0x600CC558:('bic','r1, r1, #1'),
        0x600CC55C:('str','r2, [r0, #-0x20]'),
        0x600CC560:('subs','r0, #0x44'),
        0x600CC566:('str','r1, [r0, #0x3c]'),
        0x600CC56E:('str','r3, [r0, #0x20]'),
    },
}


def verify_pins(image):
    verify_constructor(image)
    for (lo,hi),pins in PINS.items():
        rows={i['pc']:(i['m'],i['op']) for i in decode(image,lo,hi)}
        for pc,expected in pins.items():
            if rows.get(pc)!=expected:
                raise ValueError(f'Phase69 semantic drift at {pc:#x}')


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase69 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    constructor,initialized=constructor_case(image,ram)
    worker,ready=queue_case(image,initialized,name='original_preallocated_handle',preserve_queue=True,execute_creator=True)
    c=worker['original_creator']
    expected_frame=((STACK+0x800-4)&~7)-0x44
    if (c['handle'],c['stack_buffer'],c['frame_pointer'])!=(hex(CONTROL),hex(STACK),hex(expected_frame)):
        raise ValueError('Original preallocated handle/frame provenance differs')
    if (c['prepared_pc'],c['prepared_r0'],c['prepared_status'],c['prepared_exception_return'])!=('0x60101760',hex(QUEUE),'0x1000000','0xfffffffd'):
        raise ValueError('Original prepared frame differs')
    if c['priority_word']!=1 or c['task_entry_executed'] or c['opaque_return_injected']:
        raise ValueError('Unexpected task preparation/execution result')
    if any(m['target']=='0x600ca1f8' for m in worker['models']):
        raise ValueError('Creation routine was unexpectedly stubbed')
    chain=virtual_case(image,ready,root='owner',execute_driver=True,mmio_word=8,start_transition=True)
    if chain['snapshot']['record_instance']!='0x200040e0':
        raise ValueError('Original-handle-backed class10 chain failed')
    return dict(phase=69,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        constructor_fields=constructor['fields'],original_creation_and_handle=worker,
        post_return_class10_chain=chain,
        limits=['Original task creator, state preparation and stack-frame writes execute, but no task entry or callback executes.',
                '0x600c9fd8 scheduler registration is a no-op with unchanged R0; no scheduling/context switch is reproduced.',
                'Byte fill is bounded virtual memory modeling; actual kernel synchronization and prior helper effects remain modeled.',
                'Handle value is derived by original stores from the constructor-provided preallocated structure, not injected opaque data.',
                'Original priority/frame fields are virtual construction results, not installed task state.',
                'Stage joins and virtual-MMIO word 8 are inherited; final mode publication and complete startup remain unexecuted.',
                'No physical tasks, class10 activation, USB commands, custom device code, firmware/eFuse changes or HAB bypass demonstrated.'])


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
