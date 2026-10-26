"""Verify actual signed Bruce class-selector loops and their PC literals.

This parser reads only an exactly SHA-pinned OEM update image. It explicitly
separates on-chip RAM table bases from static flash-record candidates.
"""
import argparse, hashlib, json, struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256,ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode

BASE=ASSUMED_XIP_BASE
LDR_LITERALS={
    0x60055104:0xA0,
    0x60055124:0x84,
    0x60055134:0x78,
    0x60055142:0x70,
    0x600551CC:0x50,
    0x60055282:0x64,
    0x60055288:0x60,
    0x60055322:0x28,
    0x600552F2:0x28,
}
PINS={
    0x60055142:("ldr.w","fp, [pc, #0x70]"),
    0x60055178:("ldr","r3, [r5, #4]"), # adjust from verified disasm if necessary
    0x6005517C:("add.w","r3, fp, r7"),
    0x60055182:("ldrb","r3, [r3, #0xc]"),
    0x6005518C:("ldr.w","r3, [r7, fp]"),
    0x60055194:("blx","r3"),
    0x60055196:("adds","r7, #0x10"),
    0x60055198:("cmp","r7, #0x50"),
    0x600551CC:("ldr.w","sb, [pc, #0x50]"),
    0x600551FC:("add.w","r1, sb, r6"),
    0x60055210:("ldr","r2, [r1, #4]"),
    0x60055214:("blx","r2"),
    0x60055216:("adds","r6, #0x10"),
    0x60055218:("cmp","r6, #0x50"),
    0x600552D0:("lsls","r2, r3, #4"),
    0x600552D6:("ldrb","r0, [r0, r2]"),
    0x600552DA:("cmp","r0, r2"),
}
def raw_word(data,addr):
    if addr%4 or addr<BASE or addr+4>BASE+0xFF000:raise ValueError("invalid original signed flash literal")
    return struct.unpack_from("<I",data,addr-BASE)[0]
def literal_address(pc,offset):
    return ((pc+4)&~3)+offset
def verify_pins(rows):
    for pc,expected in PINS.items():
        if rows.get(pc)!=expected:
            raise ValueError("Signed class-loop semantic anchor drift "+hex(pc)+
                             " actual "+str(rows.get(pc)))
    return True
def audit(data):
    if len(data)!=IMAGE_SIZE or hashlib.sha256(data).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact original SHA-pinned signed Bruce image")
    rows={}
    for a,b in [(0x60055100,0x600551A2),(0x600551B8,0x60055220),
                (0x600552D0,0x600552E2),(0x600552F0,0x6005533C)]:
        rows.update({i["pc"]:(i["m"],i["op"]) for i in decode(data,a,b)})
    verify_pins(rows)
    pool=[]
    for pc,imm in LDR_LITERALS.items():
        adr=literal_address(pc,imm)
        val=raw_word(data,adr)
        pool.append({"instruction":hex(pc),"literal_at":hex(adr),"value":hex(val),
                     "value_kind":("RAM" if 0x20000000<=val<0x21000000 else
                                   "XIP" if BASE<=val<BASE+0xFF000 else "other"),
                     "source_code_reached":False})
    return {
        "sha256_verified":True,
        "literal_loads":pool,
        "selector_shape":{
            "first":"0x60055178-0x6005519a",
            "first_table_base_source":"0x60055142 LDR FP PC-relative",
            "first_record_stride_bytes":16,
            "first_stop_offset":0x50,
            "first_entries_if_contiguous":5,
            "first_record_comparison":"byte at candidate record +0x0c compared with USB config byte",
            "first_indirect_method":"0x6005518c -> 0x60055194 BLX R3",
            "second":"0x600551fc-0x6005521a",
            "second_table_base_source":"0x600551cc LDR SB PC-relative",
            "second_record_stride_bytes":16,
            "second_stop_offset":0x50,
            "second_indirect_method":"0x60055210 -> 0x60055214 BLX R2",
            "third":"0x600552d0 LSL #4; 0x600552d6 LDRB indexed"
        },
        "booted_device_class4_selected":"UNVERIFIED",
        "RAM_table_contents_at_runtime":"UNVERIFIED",
        "ROM_class_record_table_same_as_RAM_table":"UNVERIFIED",
        "physical_usb_transfers":False,"firmware_writes":False
    }
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    result=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("VERIFIED SIGNED CLASS SELECTOR",json.dumps(result["selector_shape"]))
    print("PC LITERAL VALUES",json.dumps(result["literal_loads"]))
    print("LIVE OBJECT/CLASS4: NOT VERIFIED")
if __name__=="__main__":
    main()
