"""Phase 19: SHA-locked, offline vendor USB completion-handler provenance.

Reads only a locally owned 128-KiB Stadia bootloader A file. Never accesses
USB, executes firmware, flashes memory or changes fuses. Findings describe
normal constructor initialization, NOT all possible later runtime callbacks.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
RAM_GLOBAL = 0x20008B78
VENDOR_OBJECT = RAM_GLOBAL + 0x5E8
SEND_HANDLER = VENDOR_OBJECT + 0x10
SEND_CONTEXT = VENDOR_OBJECT + 0x14
RECV_HANDLER = VENDOR_OBJECT + 0x18
RECV_CONTEXT = VENDOR_OBJECT + 0x1C
SEND_THUMB = 0x6080AFFB
RECV_THUMB = 0x6080AFFD

FINGERPRINTS = {
    (0x9E30, 0x9E3C): "d6ae856663eaf48fc45ab8a301de43515f636f3d6c8be73d07f81cf6f92cf409",
    (0xA062, 0xA076): "396508bac8cf113add9f1ab58d953d550d911eac71dbcc18245c42e6f7b4792a",
    (0xBB34, 0xBB8E): "f079a3ecce0259c183fd22cd71b64576c40ee2961e7526cf5f35935bf3b008d2",
    (0x6550, 0x655A): "e2d6188a6b976d2637d0dbc0b49afc0be4fc3070443955acbc4b7bd2f266cebc",
    (0x6668, 0x668A): "9771a0d73d7fce963aac9cf45cd38a81dc74d683bccd6cf8f99610694dcbb02f",
    (0x9EB8, 0x9F1E): "a9613f46d41370eb94cfc1c8a7f231d5dc42f10f9b17e0a17f4ba643dfe89785",
    (0xAFF4, 0xB008): "6a11c058cb7d51d25cc61086e8543bbec6e58f1f03cc6fc735a781aba0fdf642",
    (0xBAC0, 0xBAE0): "eff2d6a0231541f04ced45dc2933d8d8b1461b4b9b0fc7f4e3939ebb418ab7c9",
}
# Machine-code anchor bytes at exact offsets; compare to raw little-endian image.
ANCHORS = {
    0xBACE:"0025",       # MOVS R5,#0
    0xBB3C:"c4f8e835",   # STR.W R3,[R4,#0x5E8] vendor vtable
    0xBB4A:"1a4b",       # send literal
    0xBB50:"c4f8f835",   # STR.W at +0x5F8
    0xBB54:"184b",       # receive literal
    0xBB5A:"c4f80036",   # STR.W at +0x600
    0xBB6C:"c4f8fc55",   # send context = R5 = 0
    0xBB70:"c4f80456",   # receive context = R5 = 0
    0xBB7C:"04f5bd63",   # vendor object = aggregate +0x5E8
    0xBB82:"c4f80c36",   # store vendor object pointer
    0x9EC4:"0746",       # preserve vendor object in R7
    0x9F12:"59f82630",   # select USB callback from indexed table
    0x9F16:"cde90337",   # save callback/context
    0x6668:"8c78",       # endpoint address
    0x6674:"1468",       # load registered callback
    0x6676:"5268",       # load registered context
    0x6682:"1a61",       # store context
    0x6686:"dc60",       # store callback
    0x6554:"d3e90352",   # load callback and context for completion
    0x6558:"a847",       # invoke endpoint callback
    0xA062:"8369",       # LDR R3,[R0,#0x18] underlying handler
    0xA064:"4968",       # LDR R1,[R1,#4] completion info
    0xA066:"c069",       # LDR R0,[R0,#0x1C] handler context
    0xA068:"1847",       # BX R3
    0xA06A:"1046",       # MOV R0,R2 (vendor object)
    0xA06E:"fff7f8ff",   # BL 0x6080A062
    0x9E32:"d2e90430",   # SEND LDRD [R2,#0x10]
    0x9E36:"9847",       # SEND BLX R3
    0xAFFA:"7047",       # SEND default BX LR
    0xAFFC:"7047",       # RECEIVE default BX LR
}

def ptr(image, offset):
    return struct.unpack_from("<I", image, offset)[0]

def addr(value):
    return f"0x{value:08x}"

def occurrences(image, needle):
    found, pos = [], 0
    while True:
        pos = image.find(needle, pos)
        if pos < 0:
            return found
        found.append(addr(BASE + pos))
        pos += 1

def audit(image, expected_sha256=SHA256, fingerprints=FINGERPRINTS):
    """Alternate digest/fingerprints are for synthetic tests, never the CLI."""
    if len(image) != SIZE:
        raise ValueError("Expected exactly 131072 bytes of bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("SHA-256 mismatch for known build")
    for (start, end), expected in fingerprints.items():
        if not (0 <= start < end <= SIZE):
            raise ValueError("Invalid fingerprint interval")
        if hashlib.sha256(image[start:end]).hexdigest() != expected:
            raise ValueError(f"Machine-code fingerprint mismatch at {addr(BASE+start)}")
    for offset, encoded in ANCHORS.items():
        raw = bytes.fromhex(encoded)
        if image[offset:offset+len(raw)] != raw:
            raise ValueError(f"Instruction anchor mismatch at {addr(BASE+offset)}")
    for off, value in [(0xBBAC,0x60814F34),(0xBBB4,SEND_THUMB),(0xBBB8,RECV_THUMB)]:
        if ptr(image, off) != value:
            raise ValueError(f"Unexpected constructor literal at {addr(BASE+off)}")
    if struct.unpack_from("<III", image, 0x14F34) != (
            0x60809E25, 0x6080A045, 0x60809E2D):
        raise ValueError("Unexpected vendor class dispatch table")
    if struct.unpack_from("<II", image, 0x14F24) != (
            0x60809E31, 0x6080A06B):
        raise ValueError("Unexpected USB endpoint callback table")
    if (image[0x15296:0x1529D],image[0x1529D:0x152A4]) != (
            bytes.fromhex("07058702000200"),bytes.fromhex("07050702000200")):
        raise ValueError("Unexpected vendor USB endpoint descriptors")
    return {
        "phase":19, "bootloader_build":169429,
        "sha256_verified":True, "sha256":digest, "bytes":len(image),
        "device_access":False, "usb_commands_sent":False,
        "flash_or_fuse_writes":False,
        "vendor_object":{
            "base":addr(VENDOR_OBJECT),"global_base":addr(RAM_GLOBAL),
            "constructor":"0x6080bac0","vendor_class_vtable":"0x60814f34"},
        "callback_path":{
            "endpoint_registration":"0x60809f16 -> 0x60806674 -> 0x60806682/0x60806686",
            "usb_completion":"0x60806554 -> 0x60806558",
            "bulk_out_adapter":"0x6080a06a",
            "vendor_completion_forwarder":"0x6080a062"},
        "initial_completion_handlers":{
            "bulk_in_0x87":{
                "handler_ram":addr(SEND_HANDLER),"context_ram":addr(SEND_CONTEXT),
                "literal":addr(BASE+0xBBB4),"thumb":addr(SEND_THUMB),
                "handler":addr(SEND_THUMB&~1),"machine_code":"7047",
                "meaning":"BX LR; return without processing", "initial_context":0},
            "bulk_out_0x07":{
                "handler_ram":addr(RECV_HANDLER),"context_ram":addr(RECV_CONTEXT),
                "literal":addr(BASE+0xBBB8),"thumb":addr(RECV_THUMB),
                "handler":addr(RECV_THUMB&~1),"machine_code":"7047",
                "meaning":"BX LR; return without processing", "initial_context":0}},
        "literal_opcode_scan":{
            "exact_recv_store_0x600":occurrences(image,bytes.fromhex("c4f80036")),
            "limitation":"Exact encoding only: other stores or later dynamic callback registration remain possible"},
        "later_handler_replacement":"NOT RULED OUT",
        "usb_packet_parser_on_this_initial_path":"NONE; INITIAL HANDLER IS A STUB",
        "other_update_routes":"NOT EXCLUDED",
        "usb_to_flash_writer":"NOT DEMONSTRATED",
        "hab_closed_bypass":"NOT DEMONSTRATED",
        "custom_firmware_execution":"NOT DEMONSTRATED",
        "scope":"Normal startup initial values, not a live RAM measurement or whole-program audit",
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader", type=Path)
    p.add_argument("--out", type=Path)
    a=p.parse_args()
    content=json.dumps(audit(a.bootloader.read_bytes()),indent=2)+"\n"
    if a.out:
        a.out.write_text(content,encoding="utf-8")
    else:
        print(content,end="")

if __name__ == "__main__":
    main()
