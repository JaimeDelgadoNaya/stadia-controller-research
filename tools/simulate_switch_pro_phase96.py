"""Phase 96: offline Stadia Bruce -> original Switch Pro (NS1) protocol model.

No physical USB/Bluetooth/network I/O, no device identity from bonding data,
no image loading, firmware patching, SDP, or fuse operations.
This is a protocol model, not a claim of Nintendo Switch 2 acceptance.
"""
from dataclasses import dataclass

# Bruce from user-supplied third-party disassembly:
# 11 bytes = 03 hat uint16_le_buttons lx ly rx ry lt rt consumer.
SOURCE_BUTTONS = {"capture":0,"assistant":1,"lt":2,"rt":3,"home":4,
                  "plus":5,"minus":6,"rs":7,"ls":8,"r":9,"l":10,
                  "y":11,"x":12,"b":13,"a":14}
PRO_BITS = {"y":(0,0),"x":(0,1),"b":(0,2),"a":(0,3),
            "r":(0,6),"zr":(0,7),"minus":(1,0),"plus":(1,1),
            "rs":(1,2),"ls":(1,3),"home":(1,4),"capture":(1,5),
            "down":(2,0),"up":(2,1),"right":(2,2),"left":(2,3),
            "l":(2,6),"zl":(2,7)}
HATS = {0:("up",),1:("up","right"),2:("right",),3:("down","right"),
        4:("down",),5:("down","left"),6:("left",),7:("up","left"),8:()}
FAKE_MAC = bytes.fromhex("020000000001")


class ProtocolGap(RuntimeError):
    """Missing Nintendo protocol functionality; fail closed."""


def axis8_to_12(value):
    if not isinstance(value,int) or not 0<=value<=255:
        raise ValueError("Invalid 8-bit axis")
    return min(4095,((max(1,value)-1)*4095+127)//254)


def pack12(x,y):
    if not all(isinstance(v,int) and 0<=v<=4095 for v in (x,y)):
        raise ValueError("Sticks must be unsigned 12-bit values")
    return bytes([x&255,((x>>8)&15)|((y&15)<<4),(y>>4)&255])


def unpack12(data):
    if not isinstance(data,bytes) or len(data)!=3:
        raise ValueError("Need exactly three stick bytes")
    return data[0]|((data[1]&15)<<8),(data[1]>>4)|(data[2]<<4)


def translate_bruce(packet, *, face_layout="positions",trigger_threshold=128,tick=0):
    """Make one 64-byte synthetic NS1 Pro 0x30 report.

    The 8-bit source axes cannot recover genuine 12-bit resolution; the
    analog source triggers become digital Nintendo ZL/ZR. IMU is all zero.
    """
    if not isinstance(packet,bytes) or len(packet)!=11 or packet[0]!=3:
        raise ValueError("Expected Bruce report ID 03 plus ten bytes")
    if packet[1] not in HATS:
        raise ValueError("Invalid hat value")
    if packet[3]&128:
        raise ValueError("Reserved button bit set")
    if face_layout not in ("positions","labels"):
        raise ValueError("Unknown face-button policy")
    if not isinstance(trigger_threshold,int) or not 0<=trigger_threshold<=255:
        raise ValueError("Invalid trigger threshold")
    if not isinstance(tick,int) or tick<0:
        raise ValueError("Invalid tick")
    bitmap=int.from_bytes(packet[2:4],"little")
    source={name for name,bit in SOURCE_BUTTONS.items() if bitmap&(1<<bit)}
    targets=set(HATS[packet[1]])
    face={"a":"b","b":"a","x":"y","y":"x"} if face_layout=="positions" else {
        "a":"a","b":"b","x":"x","y":"y"}
    for key in source:
        if key in face:
            targets.add(face[key])
        elif key in PRO_BITS:
            targets.add(key)
    if "lt" in source or packet[8]>=trigger_threshold:
        targets.add("zl")
    if "rt" in source or packet[9]>=trigger_threshold:
        targets.add("zr")
    buttons=[0,0,0]
    for name in targets:
        column,bit=PRO_BITS[name]
        buttons[column]|=1<<bit
    out=bytearray(64)
    out[0]=0x30
    out[1]=tick&255
    out[2]=0x80  # synthetic connection status
    out[3:6]=bytes(buttons)
    out[6:9]=pack12(axis8_to_12(packet[4]),axis8_to_12(packet[5]))
    out[9:12]=pack12(axis8_to_12(packet[6]),axis8_to_12(packet[7]))
    out[12]=8
    # 36-byte IMU area and rest of report deliberately zero, no sensor data.
    return bytes(out)


@dataclass
class VirtualNS1Pro:
    """USB report handler with only a documented subset of NS1 commands."""
    state: str = "fresh"
    report_mode: int = 0
    timer: int = 0

    def command(self,data):
        if not isinstance(data,bytes) or len(data)<2:
            raise ProtocolGap("Truncated report")
        rid=data[0]
        if rid==0x80:
            sub=data[1]
            if sub==1 and self.state=="fresh":
                self.state="identified"
                return bytes([0x81,1,0,3])+FAKE_MAC
            if sub==2 and self.state in ("identified","baud"):
                self.state="handshake"
                return bytes([0x81,2])
            if sub==3 and self.state=="handshake":
                self.state="baud"
                return bytes([0x81,3])
            if sub==4 and self.state in ("handshake","baud"):
                self.state="stream"
                return None
            raise ProtocolGap("Unsupported or out-of-order init")
        if rid==1:
            if self.state!="stream" or len(data)<11:
                raise ProtocolGap("Expected complete 0x01 frame after init")
            sub=data[10]
            if sub==0x10:
                raise ProtocolGap("SPI factory calibration not modeled")
            if sub!=3 or len(data)<12 or data[11]!=0x30:
                raise ProtocolGap("Unsupported subcommand/report mode")
            self.report_mode=0x30
            return bytes([0x21,0,0x80])+bytes(10)+bytes([0x80,3])
        raise ProtocolGap("Unknown report ID")

    def sample(self,bruce,layout="positions"):
        if self.state!="stream" or self.report_mode!=0x30:
            raise ProtocolGap("Full USB init/report mode not completed")
        self.timer=(self.timer+1)&255
        return translate_bruce(bruce,face_layout=layout,tick=self.timer)


def demonstration():
    d=VirtualNS1Pro()
    replies=[d.command(x).hex() if x!=b"\x80\x04" else d.command(x)
             for x in (b"\x80\x01",b"\x80\x02",b"\x80\x03",b"\x80\x04")]
    mode=d.command(bytes([1,0])+bytes(8)+bytes([3,0x30]))
    neutral=bytes([3,8,0,0,128,128,128,128,0,0,0])
    report=d.sample(neutral)
    try:
        d.command(bytes([1,0])+bytes(8)+bytes([0x10])+bytes(5))
    except ProtocolGap as error:
        blocked=str(error)
    else:
        raise AssertionError("The SPI gap must remain visible")
    return {"virtual_usb_replies":replies,"mode_ack":mode[13],
            "report_id":report[0],"report_size":len(report),
            "source_sticks":(128,128,128,128),
            "packed_neutral_sticks":report[6:12].hex(),
            "spi_calibration_blocker":blocked,
            "switch_2_compatibility_proven":False,
            "retail_hab_closed_boot_proven":False,
            "hardware_or_console_access":False}
