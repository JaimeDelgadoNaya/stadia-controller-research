"""Compare archived vendor-signed Bruce prod/stage/dev variants offline.

This validates file identities, CMS signatures and signer's embedded public
keys. Matching embedded keys never proves the corresponding SRK is accepted
by the *physical* device. Does not create/install firmware or make USB calls.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tools.verify_hab import verify as verify_hab, hab_object, take

EXPECTED_GIT_BLOBS={
    "prod":"387001dba1eaa5fa4cc61e3101d28a77ba8fb5b4",
    "stage":"24bc5ac853a473ad0bbc5ddf542ce0fcbb645f74",
    "dev":"1d17db94272fa05e79e6838d664d92c29c26687d",
}
SIZE=1050984
BASE=0x60040000
IVT=0xFF000
CSF=0xFF030
SIGN_LEN=0xFF030


def git_blob_id(blob):
    return hashlib.sha1(b"blob "+str(len(blob)).encode()+b"\0"+blob).hexdigest()


def certificate_keys(blob):
    """Read embedded X.509 public-key fingerprints, not a fuse trust anchor."""
    csf=hab_object(blob,CSF,0xD4)
    keys={}
    cursor=4
    while cursor<len(csf):
        header=take(csf,cursor,4)
        sz=int.from_bytes(header[1:3],"big")
        if sz<4:
            raise ValueError("Malformed CSF command")
        command=take(csf,cursor,sz)
        if command[0]==0xBE and sz==12 and command[4]==9:
            at=CSF+int.from_bytes(command[8:12],"big")
            cert_data=hab_object(blob,at,0xD7)
            cert=x509.load_der_x509_certificate(cert_data[4:])
            der=cert.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            keys[str(command[7])]={
                "public_key_spki_sha256":hashlib.sha256(der).hexdigest(),
                "subject":cert.subject.rfc4514_string(),
                "issuer":cert.issuer.rfc4514_string(),
            }
        cursor+=sz
    if not keys:
        raise ValueError("Expected embedded signer certificate import")
    return keys


def verify_variant(label,blob):
    if label not in EXPECTED_GIT_BLOBS:
        raise ValueError("Unknown provenance label")
    if len(blob)!=SIZE or git_blob_id(blob)!=EXPECTED_GIT_BLOBS[label]:
        raise ValueError("Size/Git blob identity mismatch: "+label)
    ivt=struct.unpack_from("<8I",blob,IVT)
    if ivt[0]!=0x412000D1 or ivt[5]!=BASE+IVT or ivt[6]!=BASE+CSF:
        raise ValueError("Unexpected IVT layout for "+label)
    result=verify_hab(blob,BASE,CSF)
    if not all(x["digest_matches"] and x["rsa_signature_valid"]
                   for x in result["signatures"]):
        raise ValueError("Cryptographic verification failed: "+label)
    signed=[(int(b["file_offset"],16),b["bytes"])
            for x in result["signatures"] for b in x["blocks"]
            if b.get("type")!="CSF commands"]
    if signed!=[(0,SIGN_LEN)]:
        raise ValueError("Authenticated block coverage differs: "+label)
    return {
        "variant":label,"git_blob_sha1":git_blob_id(blob),
        "sha256":hashlib.sha256(blob).hexdigest(),
        "ivt_entry":hex(ivt[1]),"reset_vector_0":hex(struct.unpack_from("<I",blob,4)[0]),
        "embedded_rsa_cms_signatures_valid":len(result["signatures"]),
        "authenticated_range":[hex(0),hex(SIGN_LEN)],
        "embedded_certificates":certificate_keys(blob),
        "code_region_sha256":hashlib.sha256(blob[:IVT]).hexdigest(),
        "physical_HAB_acceptance":"NOT TESTED",
    }


def compare_images(prod,stage,dev):
    samples={"prod":prod,"stage":stage,"dev":dev}
    results={label:verify_variant(label,blob) for label,blob in samples.items()}
    prod_keys={v["public_key_spki_sha256"]
               for v in results["prod"]["embedded_certificates"].values()}
    comparisons={}
    for label in ("stage","dev"):
        candidate_keys={v["public_key_spki_sha256"]
                        for v in results[label]["embedded_certificates"].values()}
        changed=sum(1 for a,b in zip(prod[:IVT],samples[label][:IVT]) if a!=b)
        changed_signed=sum(1 for a,b in zip(prod[:SIGN_LEN],samples[label][:SIGN_LEN]) if a!=b)
        changed_tail=sum(1 for a,b in zip(prod[SIGN_LEN:],samples[label][SIGN_LEN:]) if a!=b)
        first_diff=next((i for i,(a,b) in enumerate(zip(prod,samples[label]))
                         if a!=b),None)
        comparisons[label]={
            "same_full_image_as_prod":results[label]["sha256"]==results["prod"]["sha256"],
            "different_authenticated_code_bytes":changed,
            "different_full_authenticated_block_bytes":changed_signed,
            "different_post_authenticated_bytes":changed_tail,
            "first_differing_file_offset":hex(first_diff) if first_diff is not None else None,
            "same_original_application_logic_as_prod":changed==0,
            "shares_embedded_signer_public_key_with_prod":bool(prod_keys & candidate_keys),
            "image_boots_on_HAB_CLOSED_prod_controller":"NOT TESTED",
            "debug_mode_unlocked":"NOT DEMONSTRATED",
            "OEM_dev_or_stage_build_is_unsigned_custom_code":False,
        }
    return {
        "provenance":"StadiaMemories/firmware exact immutable Git blob fingerprints",
        "images":results,"comparisons_to_prod":comparisons,
        "interpretation":"Valid OEM signed dev/stage firmware is NOT a user-signed arbitrary firmware route; SRK fuse trust and board compatibility cannot be inferred from the embedded X.509 key alone.",
        "hardware_access":False,"USB_transmissions":False,"flash_writes":False,
        "HAB_bypass":False,"recoverability":"NOT DEMONSTRATED",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("prod",type=Path)
    p.add_argument("stage",type=Path)
    p.add_argument("dev",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    report=compare_images(args.prod.read_bytes(),args.stage.read_bytes(),
                          args.dev.read_bytes())
    doc=json.dumps(report,indent=2)+"\n"
    if args.out:
        args.out.write_text(doc,encoding="utf-8")
    else:
        print(doc,end="")


if __name__=="__main__":
    main()
