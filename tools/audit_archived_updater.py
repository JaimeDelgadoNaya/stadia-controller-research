"""Static audit of Google Stadia's archived browser firmware updater.

Read-only. Never executes JavaScript, speaks to USB, alters firmware or runs
the flashloader. Download controller/app_combined.js from hazrpg/stadia-flasher
into a local ignored directory, then run this file against that local copy.
The pinned Git blob identity protects against applying findings to other JS.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

SOURCE_URL = "https://github.com/hazrpg/stadia-flasher/blob/main/controller/app_combined.js"
SOURCE_BLOB_SHA1 = "3c877738c12e7d5750714cd0770935ad39bd9990"
SOURCE_BYTES = 149810

# Selective anchors in named Closure-minified functions. These pin the
# evidence to operations rather than merely trusting inferred symbol names.
FUNCTION_ANCHORS = {
    "bj": ("cj(a,{P:1028,address:536870912,Aa:0,Ia:b.byteLength,data:0})",
           "a.device.sendReport(2,e)",
           "cj(a,{P:2827,address:536871936,Aa:0,Ia:0,data:0})"),
    "cj": ("d.setUint16(0,b.P,!1)", "d.setUint32(2,b.address,!1)",
           "a.device.sendReport(1,c)"),
    "Zi": ("8137===b.device.vendorId&&309===b.device.productId&&4===c.reportId",
            "5538===b.device.vendorId&&115===b.device.productId",
            "3===c.reportId?$i(b,c.data):4===c.reportId?aj(b,c.data)"),
    "fj": ("gj(a)","hj(a)","ij(a,f)","jj(a,1074757680,",
           "jj(a,1074757684,0)","jj(a,1074757688,0)",
           "g=Ri(b)","kj(a,h,","lj(a,b,g.da.offset,","x(l,a.reset(),20)"),
    "hj": ('id("flashloader_fcb_get_vendor_id.bin")',"nj(a,8192,b)",
           "pj(a)","rj(a)"),
    "ij": ('"Giga-16m"===b',"jj(a,8192,3221225990)",
           '"Winbond-16m"!==b','id("flashloader_fcb_w25q128jw.bin")'),
    "mj": ("f=16384<e?16384:e","sj(a,{P:2,flags:0,parameters:[b,f,0]})"),
    "nj": ("sj(a,{P:4,flags:1,parameters:[b,c.byteLength,0]})",
           "e=512","uj(a,c.slice(f,g))","tj(a)"),
    "sj": ("g.setUint8(0,b.P)","g.setUint8(1,b.flags)",
           "g.setUint32(4*h+4,b.parameters[h],!0)","a.device.sendReport(1,d)"),
    "uj": ("dj(a,2)","a.device.sendReport(2,c)"),
    "Ri": ("b=b.every(function(k,l){return k===Pi[l]})",
           "c+=4096","1953699234!==e","1200016776!==d",
           "256!==f","a=Qi(h)"),
    "Qi": ('name:"Application A",offset:1610874880',
           'name:"Application B",offset:1619263488',
           'name:"Bootloader A",offset:1619001344',
           'name:"Bootloader B",offset:1619132416'),
    "kj": ("mj(a,1610616832,b.byteLength,","nj(a,1610616832,b,"),
    "lj": ("mj(a,c,b.byteLength,","nj(a,c,b,"),
    "wm": ('id("restricted_ivt_flashloader.bin")',"bj(a,b)"),
    "xm": ("lm()","fj(a,c,","zj()","Dj(f)"),
    "lm": ('return id(jm[a+"_"+d])',),
    "Dj": ("Bj(a,129)","b.getUint32(0,!0)"),
    "Ej": ("Cj(a)","Bj(a,132)"),
    "Bj": ('recipient:"interface",request:b,requestType:"class",value:0',
           "a.controlTransferIn(d,64)"),
    "Cj": ('recipient:"interface",request:131,requestType:"class",value:0',
           "a.controlTransferOut(c)"),
    "Aj": ("255===d.alternate.interfaceClass",
           "a.claimInterface(b.interfaceNumber)"),
    "sm": ("10>X.U",),
}
GLOBAL_ANCHORS = (
    "mm=[{vendorId:5538,productId:115},{vendorId:6353,productId:37888},{vendorId:6353,productId:37995},{vendorId:8137,productId:309}]",
    "Pi=[209,0,32,65]",
    'jm={bruce_dev:"bruce_dvt_a_dev_signed.bin",bruce_dvt:"bruce_dvt_a_stage_signed.bin",bruce_pvt:"bruce_pvt_a_prod_signed.bin"',
    "km={bruce:337784,gotham:282115}",
    "Zi.prototype.reset=function()",
)

MODES = [
    {"mode":"normal","vid":"0x18d1","pid":"0x9400","api":"WebUSB",
     "purpose":"version and battery checks"},
    {"mode":"bootloader","vid":"0x18d1","pid":"0x946b","api":"HID/WebUSB enumerated",
     "purpose":"mode selection; not the archived host firmware data recipient"},
    {"mode":"rom_sdp","vid":"0x1fc9","pid":"0x0135","api":"WebHID",
     "purpose":"signed loader sent to RAM, followed by jump"},
    {"mode":"signed_ram_flashloader","vid":"0x15a2","pid":"0x0073","api":"WebHID",
     "purpose":"flash configure, erase, write and reset"},
]

HOST_MATRIX = [
    {"stage":1,"mode":"normal","host":"WebUSB class interface IN request 0x81, 64 bytes; version LE32",
     "functions":["Aj","Bj","Dj"],"receiver":"normal application USB class",
     "receiver_provenance":"version measured previously; exact code handler not yet matched",
     "checks":"version only, not cryptographic validation"},
    {"stage":2,"mode":"normal","host":"OUT class interface 0x83, delay, IN class interface 0x84; battery 16-bit",
     "functions":["Cj","Ej"],"receiver":"normal application USB class",
     "receiver_provenance":"host calls verified; exact firmware handler unresolved",
     "checks":"UI battery minimum 10 percent if known"},
    {"stage":3,"mode":"rom_sdp","host":"HID report 1 SDP WRITE_FILE 0x0404 to RAM 0x20000000; HID report 2 payload chunks; SDP JUMP_ADDRESS 0x0b0b at 0x20000400",
     "functions":["wm","bj","cj"],"receiver":"NXP ROM SDP",
     "receiver_provenance":"command IDs independently agree with stadiatool/sdp.py; ROM bytes not disassembled",
     "checks":"on tested controller HAB CLOSED; previously accepted original signed RAM loader, no unsigned payload execution shown"},
    {"stage":4,"mode":"signed_ram_flashloader","host":"HID report 1 little-endian flashloader command; report 2 data",
     "functions":["sj","hj","ij","pj"],"receiver":"vendor restricted signed RAM flashloader",
     "receiver_provenance":"command tags corroborated by stadiatool/flashloader.py; receiver handlers not all disassembled",
     "checks":"detect NXP MCU and flash type, configure FlexSPI, check command statuses"},
    {"stage":5,"mode":"signed_ram_flashloader","host":"choose Google signed image by family/hardware variant; check build header/footer/size/reset vector partition, optional IVT",
     "functions":["lm","Ri","Qi","fj","kj"],"receiver":"host metadata parser followed by signed RAM flashloader",
     "receiver_provenance":"host code paths verified",
     "checks":"host metadata/partition checks are NOT cryptographic signature checks"},
    {"stage":6,"mode":"signed_ram_flashloader","host":"command 0x02 erase in <=16 KiB chunks; command 0x04 WriteMemory with report 2 <=512-byte chunks; command 0x0b Reset",
     "functions":["mj","nj","lj","fj"],"receiver":"signed RAM flashloader",
     "receiver_provenance":"tags match separate stadiatool/flashloader.py implementation",
     "checks":"nonzero generic command-status errors; no demonstrated acceptance of arbitrary unsigned firmware"},
    {"stage":7,"mode":"normal","host":"reconnect WebUSB, version request 0x81, compare installed build with expected",
     "functions":["xm","Dj"],"receiver":"normal firmware on successful restart",
     "receiver_provenance":"host code and prior physical version read",
     "checks":"build check is not whole-flash cryptographic attestation or guaranteed recovery"},
]

def git_blob_sha1(data):
    if not isinstance(data, bytes):
        raise TypeError("Raw file bytes required")
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii")+data).hexdigest()

def function_body(source, name):
    """Named Closure functions; never eval the source."""
    m=re.search(r"(?<![\w$])function\s+"+re.escape(name)+r"\s*\(",source)
    if not m:
        raise ValueError(f"Missing updater function {name}")
    remainder=source[m.end():]
    nxt=re.search(r"(?<![\w$])function\s+[$A-Za-z_][\w$]*\s*\(",remainder)
    end=len(source) if not nxt else m.end()+nxt.start()
    return source[m.start():end]

def audit(raw,expected_blob=SOURCE_BLOB_SHA1,expected_size=SOURCE_BYTES):
    if len(raw)!=expected_size:
        raise ValueError(f"Archived JS size mismatch: expected {expected_size}")
    digest=git_blob_sha1(raw)
    if digest!=expected_blob:
        raise ValueError("Archived JS Git blob SHA-1 mismatch")
    try:
        source=raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Expected UTF-8 JavaScript") from exc
    confirmed={}
    for name,anchors in FUNCTION_ANCHORS.items():
        body=function_body(source,name)
        for anchor in anchors:
            if anchor not in body:
                raise ValueError(f"Missing {name} anchor: {anchor[:60]}")
        confirmed[name]=len(anchors)
    for anchor in GLOBAL_ANCHORS:
        if anchor not in source:
            raise ValueError(f"Missing global anchor: {anchor[:60]}")
    transfer_sites={
        "webusb_control_in":source.count("controlTransferIn("),
        "webusb_control_out":source.count("controlTransferOut("),
        "webusb_bulk_out":source.count(".transferOut("),
        "webusb_bulk_in":source.count(".transferIn("),
        "webhid_send_report":source.count(".sendReport("),
    }
    if transfer_sites!={"webusb_control_in":1,"webusb_control_out":1,
                         "webusb_bulk_out":0,"webusb_bulk_in":0,
                         "webhid_send_report":4}:
        raise ValueError(f"Unexpected USB callsite inventory: {transfer_sites!r}")
    return {
        "research":"host updater actual WebUSB/WebHID pathway",
        "source":SOURCE_URL,"source_git_blob_sha1":digest,"source_bytes":len(raw),
        "identity_verified":True,"javascript_executed":False,
        "hardware_access":False,"usb_transfers":False,"flash_writes":False,
        "validated_named_functions":confirmed,
        "transfer_calls":transfer_sites,"modes":MODES,
        "host_to_receiver_matrix":HOST_MATRIX,
        "critical_distinctions":{
            "oem_0x81":"read version, NOT updater write",
            "bootloader_A_bulk_OUT_0x07":"NOT used as a flash data endpoint by this archived host script",
            "flash_write_location":"signed RAM flashloader 0x15a2:0x0073, NOT application callback 0x60058b68",
            "ROM_SDP":"acceptance of Google's signed RAM loader on one HAB CLOSED controller measured previously",
            "host_image_metadata":"header/footer/reset partition, not signature validation",
            "recovery":"not demonstrated for custom images or interrupted writes; bootloader B slot empty in tested unit",
            "app_message_byte_5":"not matched to any update-packet request",
        },
        "decision":{
            "package_A":"COMPLETE: actual host command sequence and receiving COMPONENTS; not all receiver function addresses",
            "host_firmware_write_procedure":"CONFIRMED IN ARCHIVED HOST CODE, NOT EXECUTED IN THIS RESEARCH",
            "firmware_unsigned_custom_execution":"NOT DEMONSTRATED",
            "recoverable_custom_execution":"NOT DEMONSTRATED",
            "package_B":"ONE REMAINING BOUNDED PACKAGE: image authenticity/boot and recovery check, then STOP/GO",
        }
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("js",type=Path,help="Downloaded archived JavaScript in local ignored folder")
    p.add_argument("--out",type=Path,help="Private local JSON output")
    args=p.parse_args()
    output=json.dumps(audit(args.js.read_bytes()),indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")

if __name__=="__main__":
    main()
