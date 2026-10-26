"""Original registration and ITCM list/critical-section helpers, offline.

Cold scheduler RAM and a virtual system-register page are explicit models.
List insertion is not task execution, a real interrupt or a context switch.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET,DATA_SOURCE_OFFSET,DATA_DESTINATION
from tools.audit_task_handle_phase69 import verify_pins as verify_creator
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_workqueue_constructor_phase68 import constructor_case,CONTROL
from tools.audit_pending_workqueue_phase67 import queue_case
from tools.audit_class10_instance_phase65 import virtual_case
from tools.audit_usb_provider_phase63 import BASE

VENEERS={0x6013D360:0x7D65,0x6013D000:0x7DAD,0x6013D060:0xB2E9,0x6013D188:0xB2FF}
PINS={
    0x600C9FDE:('bl','#0x6013d360'),
    0x600C9FEC:('str','r2, [r3]'),
    0x600C9FF4:('str','r4, [r5]'),
    0x600CA006:('bl','#0x6013d060'),
    0x600CA054:('str','r3, [r1]'),
    0x600CA05C:('bl','#0x6013d188'),
    0x600CA060:('bl','#0x6013d000'),
}


def verify_pins(image):
    verify_creator(image)
    rows={i['pc']:(i['m'],i['op']) for i in decode(image,0x600C9FD8,0x600CA09E)}
    for pc,expected in PINS.items():
        if rows.get(pc)!=expected:
            raise ValueError(f'Phase70 registration semantic drift at {pc:#x}')
    for veneer,target in VENEERS.items():
        row=decode(image,veneer,veneer+4)
        if [(i['m'],i['op']) for i in row]!=[('ldr.w','pc, [pc, #-0x0]')]:
            raise ValueError('Phase70 veneer opcode drift')
        if struct.unpack_from('<I',image,veneer+4-BASE)[0]!=target:
            raise ValueError('Phase70 ITCM target drift')
    source=DATA_SOURCE_OFFSET+0x20003D68-DATA_DESTINATION
    if struct.unpack_from('<I',image,source)[0]!=0xAAAAAAAA:
        raise ValueError('Phase70 original nesting sentinel drift')


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase70 exact SHA-pinned OEM required')
    verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    _,initialized=constructor_case(image,ram)
    cases=[]
    balanced=None
    for nesting in (None,0):
        worker,state=queue_case(image,initialized,name='signed_nesting_sentinel' if nesting is None else 'zero_nesting_test_vector',
            preserve_queue=True,execute_creator=True,execute_registration=True,critical_nesting=nesting)
        r=worker['original_registration']
        if r['task_count']!=1 or r['current_task']!=hex(CONTROL) or r['ready_bitmap']!='0x2' or r['ready_count']!=1:
            raise ValueError('Original scheduler globals/list count differ')
        if (r['ready_next'],r['ready_previous'],r['node_container'])!=(hex(CONTROL+4),hex(CONTROL+4),r['ready_list']):
            raise ValueError('Original ready-list linkage differs')
        expected_nesting,expected_mask=('0xaaaaaaaa','0x50') if nesting is None else ('0x0','0x0')
        if (r['final_critical_nesting'],r['virtual_basepri'])!=(expected_nesting,expected_mask):
            raise ValueError('Original critical helper state differs')
        if not r['itcm_helpers_executed'] or r['task_entry_executed'] or worker['original_creator']['registration_stubbed']:
            raise ValueError('Original-registration execution boundary differs')
        if any(m['target']=='0x600c9fd8' for m in worker['models']):
            raise ValueError('Registration unexpectedly stubbed')
        cases.append(worker)
        if nesting==0:
            balanced=state
    chain=virtual_case(image,balanced,root='owner',execute_driver=True,mmio_word=8,start_transition=True)
    if chain['snapshot']['record_instance']!='0x200040e0':
        raise ValueError('Registered-state class10 chain failed')
    return dict(phase=70,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        registration='0x600c9fd8',itcm_veneer_targets={hex(k):hex(v) for k,v in VENEERS.items()},
        itcm_source_offset=hex(ITCM_SOURCE_OFFSET),original_nesting_word=dict(address='0x20003d68',value='0xaaaaaaaa'),
        original_registration_cases=cases,post_registration_class10_chain=chain,
        limits=['Cold scheduler globals are virtual input from the partial constructor snapshot, not installed scheduler state.',
                'ITCM bytes are copied from the signed image and executed at runtime addresses; full startup is not executed.',
                'Registration, list insertion and critical helpers execute original code, but no scheduler start/context switch/task entry executes.',
                'System page 0xe000e000 is plain virtual memory; real NVIC/interrupt behavior and timing are not modeled.',
                'Signed nesting sentinel is preserved in one case; a separate zero-nesting test vector restores virtual BASEPRI to zero.',
                'Only the zero-nesting case is joined to the later class10 stage; this does not establish real startup normalization.',
                'Prior constructor, synchronization, caller helpers and byte-fill models remain.',
                'Later stage uses a new virtual machine/register context and synthetic USB MMIO 8; final mode publication and callbacks remain unexecuted.',
                'No physical task scheduling, class10 activation, device commands, firmware/eFuse change, custom code or HAB bypass.'])


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
