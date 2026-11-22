"""Phase 99: offline Stadia Bruce -> Xbox 360 wired 20-byte XUSB conversion.

Source: user-supplied bluetooth-image-public.md §8/§9 (Bruce 337784).
No USB, device I/O, flash, SDP, signing, bonding or console authentication.
"""
from dataclasses import dataclass
import struct

BRUCE_BITS={"capture":0,"assistant":1,"lt_click":2,"rt_click":3,"guide":4,
            "start":5,"back":6,"rs":7,"ls":8,"rb":9,"lb":10,
            "y":11,"x":12,"b":13,"a":14}
XUSB_BITS={"up":0,"down":1,"left":2,"right":3,"start":4,"back":5,
           "ls":6,"rs":7,"lb":8,"rb":9,"guide":10,
           "a":12,"b":13,"x":14,"y":15}
HATS={0:("up",),1:("up","right"),2:("right",),3:("down","right"),
      4:("down",),5:("down","left"),6:("left",),7:("up","left"),8:()}
RAW_BUTTON_OFFSETS={"a":8,"b":9,"x":10,"y":11,"up":12,"down":13,
                    "left":14,"right":15,"lb":16,"rb":17,"ls":20,"rs":21,
                    "back":22,"start":23,"assistant":24,"capture":25,"guide":26}

class PacketError(ValueError): pass

@dataclass(frozen=True)
class StadiaInput:
    buttons:frozenset[str]
    lx:int
    ly:int
    rx:int
    ry:int
    lt:int
    rt:int
    source_bits:int
    consumer:int=0

def parse_bruce_hid(packet:bytes)->StadiaInput:
    if type(packet) is not bytes or len(packet)!=11 or packet[0]!=3:
        raise PacketError("Expected 11-byte Bruce HID report 0x03")
    if packet[1] not in HATS:
        raise PacketError("Invalid hat")
    mask=int.from_bytes(packet[2:4],"little")
    if mask & 0x8000:raise PacketError("Reserved button bit")
    buttons={name for name,bit in BRUCE_BITS.items() if mask & (1<<bit)}
    buttons.update(HATS[packet[1]])
    return StadiaInput(frozenset(buttons),*packet[4:10],8,packet[10])

def parse_bruce_raw(data:bytes)->StadiaInput:
    """Synthetic pre-HID producer layout, not a live RAM reader."""
    if type(data) is not bytes or not 0x34<=len(data)<=4096:
        raise PacketError("Bad raw producer size")
    vals=struct.unpack_from("<6I",data,0x1c)
    if any(v>0x1000 for v in vals):
        raise PacketError("12-bit source out of 0..0x1000")
    buttons=frozenset(name for name,ofs in RAW_BUTTON_OFFSETS.items() if data[ofs])
    return StadiaInput(buttons,*vals,12)

def axis(value:int,bits:int)->int:
    if type(value) is not int or bits not in (8,12):
        raise PacketError("Invalid source axis")
    centre,top=(128,255) if bits==8 else (2048,4096)
    if not 0<=value<=top:raise PacketError("Axis range")
    if value<=centre:
        return -(((centre-value)*32768+centre//2)//centre)
    span=top-centre
    return ((value-centre)*32767+span//2)//span

def trigger(value:int,bits:int)->int:
    if type(value) is not int or bits not in (8,12):
        raise PacketError("Invalid trigger")
    top=255 if bits==8 else 4096
    if not 0<=value<=top:raise PacketError("Trigger range")
    return value if bits==8 else (value*255+2048)//4096

def invert_s16(n:int)->int:
    return -32768 if n==32767 else (32767 if n==-32768 else -n)

def to_xusb(src:StadiaInput,*,invert_y:bool=True)->bytes:
    """20-byte vendor XUSB INPUT, NOT HID or an enumerating USB device."""
    if not isinstance(src,StadiaInput) or type(invert_y) is not bool:
        raise PacketError("Invalid source/polarity")
    names=set(src.buttons)
    names.difference_update({"assistant","capture","lt_click","rt_click"})
    if {"up","down"}<=names:names.difference_update(("up","down"))
    if {"left","right"}<=names:names.difference_update(("left","right"))
    if names-XUSB_BITS.keys():raise PacketError("Unexpected button")
    mask=sum(1<<XUSB_BITS[n] for n in names)
    lx,ly,rx,ry=(axis(v,src.source_bits) for v in (src.lx,src.ly,src.rx,src.ry))
    if invert_y:ly,ry=invert_s16(ly),invert_s16(ry)
    return struct.pack("<BBHBBhhhh6x",0,20,mask,trigger(src.lt,src.source_bits),
                       trigger(src.rt,src.source_bits),lx,ly,rx,ry)

def decode_xusb(data:bytes)->dict:
    if type(data) is not bytes or len(data)!=20 or data[:2]!=b"\x00\x14" or any(data[14:]):
        raise PacketError("Malformed XUSB report")
    mask,lt,rt,lx,ly,rx,ry=struct.unpack_from("<HBBhhhh",data,2)
    if mask&(1<<11):raise PacketError("Reserved XUSB button bit")
    return {"buttons":sorted(n for n,b in XUSB_BITS.items() if mask&(1<<b)),
            "lt":lt,"rt":rt,"lx":lx,"ly":ly,"rx":rx,"ry":ry}

def rumble_xusb_to_stadia(data:bytes)->bytes:
    """8-byte Xbox OUT -> Bruce HID ID5, 2x unsigned little-endian u16."""
    if type(data) is not bytes or len(data)!=8 or data[:2]!=b"\x00\x08" or any(data[i] for i in (2,5,6,7)):
        raise PacketError("Invalid Xbox rumble output")
    return b"\x05"+struct.pack("<HH",data[3]*257,data[4]*257)

def led_xusb(data:bytes)->dict:
    if type(data) is not bytes or len(data)!=3 or data[:2]!=b"\x01\x03":
        raise PacketError("Invalid Xbox LED packet")
    return {"xbox_pattern":data[2],"stadia_led_command":None,
            "reason":"LP5562 RGBW wiring differs from Xbox ring"}

def demonstration()->dict:
    neutral=bytes((3,8,0,0,128,128,128,128,0,0,0))
    p=to_xusb(parse_bruce_hid(neutral))
    return {"stadia_input":neutral.hex(),"xusb_report":p.hex(),
            "decoded":decode_xusb(p),
            "rumble_example":rumble_xusb_to_stadia(bytes((0,8,0,255,128,0,0,0))).hex(),
            "physical_USB_emitted":False,"retail_HAB_closed_boot_proven":False,
            "Windows_XUSB_driver_binding_proven":False,
            "Xbox_console_authenticated":False}

if __name__=="__main__":
    import json
    print(json.dumps(demonstration(),indent=2))
