"""Original work-queue constructor and signed initializer-table linkage.

Original fields replace phase67's auxiliary-data fixtures. Kernel helper,
task creation, synchronization and physical peripherals retain explicit models.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_init_table_phase43 import verify_constructor_walker
from tools.audit_usb_class_records_phase64 import verify_sources,emulate as build_records
from tools.audit_usb_driver_phase66 import machine
from tools.audit_pending_workqueue_phase67 import QUEUE,queue_case
from tools.audit_class10_instance_phase65 import virtual_case
from tools.audit_usb_provider_phase63 import BASE

CONSTRUCTOR=0x600926D0
CONTROL=QUEUE+0x12C
STACK=QUEUE+0x200
SLOT=0xFD59C
PINS={
    (CONSTRUCTOR,0x6009272A):{
        0x600926D2:('ldr','r4, [pc, #0x58]'),
        0x600926D4:('movs','r5, #0'),
        0x600926DE:('bl','#0x601017fc'),
        0x600926F4:('strd','r5, r5, [r4, #0x58]'),
        0x600926F8:('bl','#0x600c9de4'),
        0x60092706:('add.w','r3, r4, #0x200'),
        0x6009270C:('str.w','r3, [r4, #0x1f8]'),
        0x60092710:('mov.w','r3, #0x200'),
        0x60092716:('str.w','r3, [r4, #0x1fc]'),
        0x6009271A:('add.w','r3, r4, #0x12c'),
        0x6009271E:('str','r3, [r4, #0x5c]'),
        0x60092726:('b.w','#0x60101c48'),
    },
}


def verify_pins(image):
    walker=verify_constructor_walker(image)
    start,end=(int(v,16) for v in walker['init_array_range'])
    slot=BASE+SLOT
    if not start<=slot<end or (slot-start)//4!=43 or struct.unpack_from('<I',image,SLOT)[0]!=(CONSTRUCTOR|1):
        raise ValueError('Phase68 initializer-table slot drift')
    if struct.unpack_from('<I',image,0x6009272C-BASE)[0]!=QUEUE:
        raise ValueError('Phase68 object literal drift')
    for (lo,hi),pins in PINS.items():
        rows={i['pc']:(i['m'],i['op']) for i in decode(image,lo,hi)}
        for pc,expected in pins.items():
            if rows.get(pc)!=expected:
                raise ValueError(f'Phase68 constructor semantic drift at {pc:#x}')
    return dict(walker=walker['walker_function'],table_start=hex(start),table_end=hex(end),
        entries=walker['init_array_entry_count'],index=43,source_file_offset=hex(SLOT),
        thumb_pointer=hex(CONSTRUCTOR|1),physical_walker_execution='UNMEASURED')


def constructor_case(image,ram,poison=False):
    from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_PC,UC_ARM_REG_LR
    uc=machine(image,ram)
    if poison:
        uc.mem_write(QUEUE+0x58,struct.pack('<II',0xA5A5A5A5,0x5A5A5A5A))
    steps,helpers,writes=[],[],[]

    def hook(m,pc,size,user):
        steps.append(pc)
        if pc==0x60101C48:
            m.emu_stop()  # before destructor/exit-registration wrapper.
        elif pc==0x6013D3D0:
            helpers.append(dict(target=hex(pc),input_r0=hex(m.reg_read(UC_ARM_REG_R0)),
                model='no-op returning unchanged R0; deeper kernel initialization not executed'))
            m.reg_write(UC_ARM_REG_PC,m.reg_read(UC_ARM_REG_LR))
        elif not (CONSTRUCTOR<=pc<0x6009272A or 0x601017FC<=pc<0x60101818 or 0x600C9DE4<=pc<0x600C9E64):
            raise ValueError(f'Unexpected constructor execution {pc:#x}')

    def write_hook(m,access,address,size,value,user):
        if address in (QUEUE+0x58,QUEUE+0x5C,QUEUE+0x1F8,QUEUE+0x1FC):
            writes.append(dict(pc=hex(m.reg_read(UC_ARM_REG_PC)),address=hex(address),size=size,value=hex(value)))

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    uc.emu_start(CONSTRUCTOR|1,0x10000002,count=800)
    if not steps or steps[-1]!=0x60101C48:
        raise ValueError('Constructor did not reach original tail call')
    word=lambda address:struct.unpack('<I',bytes(uc.mem_read(address,4)))[0]
    fields=dict(handle=hex(word(QUEUE+0x58)),control=hex(word(QUEUE+0x5C)),
                control_stack_pointer=hex(word(CONTROL+0xCC)),control_words=word(CONTROL+0xD0))
    if fields!=dict(handle='0x0',control=hex(CONTROL),control_stack_pointer=hex(STACK),control_words=0x200):
        raise ValueError('Original constructor fields differ')
    return dict(old_fields_poisoned=poison,fields=fields,original_writes=writes,helper_models=helpers,
        stop_before='0x60101c48',instruction_hooks=len(steps)),bytes(uc.mem_read(0x20000000,0x30000))


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase68 exact SHA-pinned OEM required')
    table=verify_pins(image)
    _,ram=build_records(image,verify_sources(image),return_ram=True)
    normal,initialized=constructor_case(image,ram)
    poison,_=constructor_case(image,ram,poison=True)
    worker,ready=queue_case(image,initialized,name='original_constructor_fields',preserve_queue=True)
    if worker['original_queue_status']!=0 or not worker['creation_primitive_reached']:
        raise ValueError('Original constructor did not supply the accepted creation path')
    if worker['initial_control_pointer']!=hex(CONTROL):
        raise ValueError('Original constructor pointer was not preserved')
    chain=virtual_case(image,ready,root='owner',execute_driver=True,mmio_word=8,start_transition=True)
    if chain['snapshot']['record_instance']!='0x200040e0':
        raise ValueError('Constructor-backed transition chain failed')
    return dict(phase=68,image_sha256=IMAGE_SHA256,exact_image_hash_verified=True,
        signed_initializer_link=table,queue_object=hex(QUEUE),original_constructor=hex(CONSTRUCTOR),
        constructor_cases=[normal,poison],pending_call_using_original_fields=worker,
        post_return_driver_class10_chain=chain,
        limits=['Constructor pointer is verified in the signed walker range; physical startup execution remains unmeasured.',
                'RAM is virtual and the main class-record snapshot inherits phase64 constructor models.',
                'One deeper kernel helper at 0x6013d3d0 is a no-op; exit/destructor registration is not executed.',
                'Handle clearing, auxiliary pointer, stack pointer and size fields execute original stores, not injected auxiliary fixtures.',
                '0x600ca1f8 still returns a modeled opaque handle; allocation/scheduler execution and task validity are not established.',
                'Caller registration/synchronization and transition guards retain explicit prior models.',
                'Driver MMIO remains plain virtual memory with synthetic word 8; final mode publication and callbacks do not execute.',
                'No physical activation, device commands, firmware/eFuse changes, custom code or HAB bypass.'])


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
