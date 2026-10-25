"""Offline HAB CSF/CMS verifier. No hardware access, downloads or firmware execution."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def take(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"Out-of-file range: offset={offset:#x}, size={size:#x}")
    return data[offset:offset + size]


def hab_object(data, offset, expected_tag):
    header = take(data, offset, 4)
    if header[0] != expected_tag:
        raise ValueError(f"Expected HAB tag {expected_tag:#x} at {offset:#x}")
    size = int.from_bytes(header[1:3], "big")
    if size < 4:
        raise ValueError("Invalid HAB object size")
    return take(data, offset, size)


def verify(data, base, csf_offset, aliases=()):
    """Verify detached CMS signatures and content digests, not the fused SRK chain.

    aliases contains explicit (address, file_offset, size) tuples. No alias is
    inferred: callers must declare a shared-IVT representation themselves.
    """
    csf = hab_object(data, csf_offset, 0xD4)
    keys, results = {}, []
    cursor = 4
    while cursor < len(csf):
        header = take(csf, cursor, 4)
        size = int.from_bytes(header[1:3], "big")
        if size < 4:
            raise ValueError("Invalid CSF command size")
        command = take(csf, cursor, size)
        if command[0] == 0xBE and size == 12 and command[4] == 9:
            location = csf_offset + int.from_bytes(command[8:12], "big")
            certificate = hab_object(data, location, 0xD7)
            keys[command[7]] = x509.load_der_x509_certificate(certificate[4:])
        elif command[0] == 0xCA:
            if size < 12 or (size - 12) % 8:
                raise ValueError("Invalid AuthenticateData block list")
            key_index = command[4]
            if key_index not in keys:
                raise ValueError("AuthenticateData references an unavailable key")
            location = csf_offset + int.from_bytes(command[8:12], "big")
            signature = hab_object(data, location, 0xD8)
            content = cms.ContentInfo.load(signature[4:], strict=True)
            if content["content_type"].native != "signed_data":
                raise ValueError("Expected CMS SignedData")
            signers = content["content"]["signer_infos"]
            if len(signers) != 1:
                raise ValueError("Expected exactly one CMS signer")
            signer = signers[0]
            if signer["digest_algorithm"]["algorithm"].native != "sha256":
                raise ValueError("This verifier supports SHA-256 only")
            if signer["signature_algorithm"]["algorithm"].native != "rsassa_pkcs1v15":
                raise ValueError("This verifier supports RSA PKCS#1 v1.5 only")
            certificate = keys[key_index]
            sid = signer["sid"]
            if sid.name != "issuer_and_serial_number" or sid.chosen["serial_number"].native != certificate.serial_number:
                raise ValueError("Signer identifier does not match installed certificate")
            if sid.chosen["issuer"].dump() != certificate.issuer.public_bytes():
                raise ValueError("Signer issuer does not match installed certificate")
            blocks, parts = [], []
            for at in range(12, size, 8):
                address, length = struct.unpack_from(">II", command, at)
                offset = address - base
                alias_used = False
                for alias_address, alias_offset, alias_size in aliases:
                    if alias_address <= address and address + length <= alias_address + alias_size:
                        offset = alias_offset + address - alias_address
                        alias_used = True
                        break
                parts.append(take(data, offset, length))
                blocks.append({"address": hex(address), "bytes": length,
                               "file_offset": hex(offset), "explicit_alias": alias_used})
            payload = b"".join(parts) if parts else csf
            attrs = signer["signed_attrs"]
            digests = [attr["values"][0].native for attr in attrs if attr["type"].native == "message_digest"]
            if len(digests) != 1 or digests[0] != hashlib.sha256(payload).digest():
                raise ValueError("Authenticated content digest mismatch")
            encoded = attrs.dump()
            if not encoded or encoded[0] != 0xA0:
                raise ValueError("Expected CMS signed attributes")
            certificate.public_key().verify(signer["signature"].native,
                                            b"\x31" + encoded[1:],
                                            padding.PKCS1v15(), hashes.SHA256())
            results.append({"key_index": key_index,
                            "certificate": certificate.subject.rfc4514_string(),
                            "digest_matches": True, "rsa_signature_valid": True,
                            "blocks": blocks or [{"file_offset": hex(csf_offset),
                                                   "bytes": len(csf), "type": "CSF commands"}]})
        cursor += size
    if not results:
        raise ValueError("No supported authentication signatures found")
    return {"sha256": hashlib.sha256(data).hexdigest(), "signatures": results,
            "scope": "CMS mathematics and content digests; fused SRK trust is not verified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--base", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--csf-offset", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--alias", action="append", default=[], metavar="ADDRESS:FILE_OFFSET:SIZE")
    args = parser.parse_args()
    aliases = [tuple(int(v, 0) for v in item.split(":")) for item in args.alias]
    if any(len(item) != 3 for item in aliases):
        parser.error("Each alias requires address, file offset and size")
    print(json.dumps(verify(args.image.read_bytes(), args.base, args.csf_offset, aliases), indent=2))


if __name__ == "__main__":
    main()
