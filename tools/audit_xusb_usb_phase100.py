"""Offline Xbox 360 XUSB original USB descriptor reference and validation.

Source: David Madison / PartsNotIncluded genuine wired 360 + USBPcap.
Reference is **not** a USB device driver or permission to ship 045e:028e.
"""
import struct

REFERENCE_DEVICE=bytes.fromhex(
    "12 01 00 02 ff ff ff 08 5e 04 8e 02 14 01 01 02 03 01"
)
# Actual 153-byte original configuration: 4 vendor interfaces.
REFERENCE_CONFIG=bytes.fromhex(" ".join((
    "09 02 99 00 04 01 00 a0 fa",
    "09 04 00 00 02 ff 5d 01 00",
    "11 21 00 01 01 25 81 14 00 00 00 00 13 01 08 00 00",
    "07 05 81 03 20 00 04",
    "07 05 01 03 20 00 08",
    "09 04 01 00 04 ff 5d 03 00",
    "1b 21 00 01 01 01 82 40 01 02 20 16 83 00 00 00 00 00 00 16 03 00 00 00 00 00 00",
    "07 05 82 03 20 00 02",
    "07 05 02 03 20 00 04",
    "07 05 83 03 20 00 40",
    "07 05 03 03 20 00 10",
    "09 04 02 00 01 ff 5d 02 00",
    "09 21 00 01 01 22 84 07 00",
    "07 05 84 03 20 00 10",
    "09 04 03 00 00 ff fd 13 04",
    "06 41 00 01 01 03",
)))

class USBStructureError(ValueError):pass

def inspect_xusb_usb(device:bytes,configuration:bytes)->dict:
    if type(device) is not bytes or len(device)!=18 or device[:2]!=b"\x12\x01":
        raise USBStructureError("Not 18-byte USB device descriptor")
    if type(configuration) is not bytes or len(configuration)<9 or configuration[:2]!=b"\x09\x02":
        raise USBStructureError("Invalid USB configuration descriptor")
    total=struct.unpack_from("<H",configuration,2)[0]
    if total!=len(configuration) or total>4096:
        raise USBStructureError("wTotalLength mismatch")
    vid,pid=struct.unpack_from("<HH",device,8)
    interfaces={}
    active=None
    off=0
    while off<len(configuration):
        length=configuration[off]
        if length<2 or off+length>len(configuration):
            raise USBStructureError("USB subdescriptor boundary error")
        raw=configuration[off:off+length]
        kind=raw[1]
        if kind==4:
            if length<9 or raw[2] in interfaces:
                raise USBStructureError("Duplicate/truncated interface")
            active=raw[2]
            interfaces[active]={"class":tuple(raw[5:8]),
                                "declared_endpoints":raw[4],"endpoints":[]}
        elif kind==5:
            if active is None or length<7:
                raise USBStructureError("Orphan/truncated endpoint")
            interfaces[active]["endpoints"].append(
                {"address":raw[2],"type":raw[3]&3,
                 "max_packet":struct.unpack_from("<H",raw,4)[0],
                 "interval":raw[6]})
        off+=length
    if set(interfaces)!=set(range(configuration[4])):
        raise USBStructureError("Interface count mismatch")
    if any(len(x["endpoints"])!=x["declared_endpoints"] for x in interfaces.values()):
        raise USBStructureError("Endpoint count mismatch")
    i0=interfaces.get(0,{})
    eps={e["address"]:e for e in i0.get("endpoints",[])}
    match=( (vid,pid)==(0x045e,0x028e) and tuple(device[4:7])==(255,255,255) and
            i0.get("class")== (255,93,1) and set(eps)=={0x81,0x01} and
            all(x["type"]==3 and x["max_packet"]==32 for x in eps.values()) and
            interfaces.get(3,{}).get("class")==(255,253,19) )
    return {"reference_vid_pid":f"{vid:04x}:{pid:04x}",
            "device_descriptor_bytes":len(device),
            "config_descriptor_bytes":len(configuration),
            "interfaces":interfaces,
            "xusb_original_reference_structure":bool(match),
            "not_generic_hid":True,
            "xusb_input_report_bytes":20,
            "retail_stadia_usb_enumeration_proven":False,
            "windows_xusb_driver_bound_proven":False,
            "xbox_console_authentication_proven":False,
            "microsoft_vid_authorized_for_commercial_use":False}

if __name__=="__main__":
    import json
    print(json.dumps(inspect_xusb_usb(REFERENCE_DEVICE,REFERENCE_CONFIG),indent=2))
