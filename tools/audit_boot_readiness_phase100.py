"""Phase 100: read-only NXP RT1061 image/IVT and HAB feasibility audit.

A CSF pointer is not signature validation. Entering SDP is not a HAB bypass.
No firmware flash, device I/O, boot attempt, USB, eFuse or FIELD_RETURN.
"""
from dataclasses import asdict,dataclass
import struct

class IVTError(ValueError):pass

@dataclass(frozen=True)
class IVT:
    offset:int
    file_size:int
    self_address:int
    entry_address:int
    boot_data_address:int
    csf_address:int
    declared_boot_size:int
    declared_minus_supplied:int
    signature_verified:bool=False
    hab_closed_boot_verified:bool=False

def inspect_ivt(blob:bytes,offset:int)->IVT:
    if type(blob) is not bytes or type(offset) is not int or not 0<=offset<=len(blob)-32:
        raise IVTError("Invalid blob / IVT offset")
    if blob[offset:offset+4]!=b"\xd1\x00\x20\x41":
        raise IVTError("Invalid NXP IVT header")
    _,entry,reserved,dcd,boot,selfptr,csf,end=struct.unpack_from("<8I",blob,offset)
    if reserved or end or not entry or not boot or not selfptr:
        raise IVTError("Unsupported/incomplete IVT")
    base=selfptr-offset
    boot_offset=boot-base
    if base<0 or not 0<=boot_offset<=len(blob)-12:
        raise IVTError("Invalid image mapping or boot data pointer")
    start,size,plugin=struct.unpack_from("<3I",blob,boot_offset)
    if plugin not in (0,1):raise IVTError("Unsupported boot plugin")
    return IVT(offset,len(blob),selfptr,entry,boot,csf,size,max(0,size-len(blob)))

def compare_bootloaders(original:bytes,candidate:bytes)->dict:
    if not original or not candidate or len(candidate)>len(original):
        raise ValueError("Original must not be shorter than candidate")
    a,b=inspect_ivt(original,0),inspect_ivt(candidate,0)
    differences=sum(x!=y for x,y in zip(original,candidate))
    return {"original_size":len(original),"candidate_size":len(candidate),
            "changes_in_shared_prefix":differences,
            "shared_prefix_equal_percent":round(100*(len(candidate)-differences)/len(candidate),4),
            "original_csf_pointer":bool(a.csf_address),
            "candidate_csf_pointer":bool(b.csf_address),
            "candidate_truncated":len(candidate)<len(original),
            "candidate_signed_valid":False,"candidate_retail_boot_proven":False,
            "safe_to_flash":False}

def hab_scenario(hab_state:str,has_csf:bool,trusted_signature_verified:bool=False,
                 sdp_entered:bool=False)->dict:
    if hab_state not in {"OPEN","CLOSED","UNKNOWN"}:
        raise ValueError("HAB must be OPEN/CLOSED/UNKNOWN")
    if any(type(x) is not bool for x in (has_csf,trusted_signature_verified,sdp_entered)):
        raise ValueError("Invalid boolean flag")
    ready=(hab_state=="CLOSED" and has_csf and trusted_signature_verified)
    return {"hab_state":hab_state,
            "candidate_signature_prerequisites_met":ready,
            "sdp_entered":sdp_entered,
            "sdp_proves_signature_bypass":False,
            "retail_flash_permitted":False,
            "field_return_permitted":False,
            "device_recovery_validated":False}

def synthetic_reference()->dict:
    """Grounded external artifact facts, not values measured on our device."""
    return {"bruce_build":337784,"gotham_stock_build_claimed":169429,
            "original_bootloader_size":131072,
            "community_usb_acm_candidate_size":94248,
            "changed_bytes_in_prefix":72,
            "community_candidate_csf_pointer":0,
            "community_ram_flashloader_bytes":98148,
            "community_ram_flashloader_ivt_offset":0x400,
            "community_ram_flashloader_declared_bytes":98304,
            "community_ram_loader_csf_pointer":0,
            "retail_closed_hab_execution_proven":False,
            "xinput_firmware_installed":False}
