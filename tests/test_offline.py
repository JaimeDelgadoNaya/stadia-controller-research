import datetime
import struct
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from tools.model_ranges import observed_range_check, nonwrapping_range_check
from tools.verify_hab import verify


def object_bytes(tag, payload):
    return bytes([tag]) + (len(payload) + 4).to_bytes(2, "big") + b"\x42" + payload


def signed_fixture():
    """Create an independent synthetic HAB/CMS fixture; no Google binaries."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(42)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    payload = bytes(range(32))
    der = (pkcs7.PKCS7SignatureBuilder().set_data(payload).add_signer(cert, key, hashes.SHA256())
           .sign(serialization.Encoding.DER,
                 [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
    cert_object = object_bytes(0xD7, cert.public_bytes(serialization.Encoding.DER))
    cert_offset = 36
    signature_offset = cert_offset + len(cert_object)
    install = b"\xBE\x00\x0C\x00\x09\x00\x00\x02" + cert_offset.to_bytes(4, "big")
    authenticate = (b"\xCA\x00\x14\x00\x02\xC5\x00\x00"
                    + signature_offset.to_bytes(4, "big") + struct.pack(">II", 0x60000000, 32))
    csf = object_bytes(0xD4, install + authenticate)
    return payload + csf + cert_object + object_bytes(0xD8, der)


class OfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = signed_fixture()

    def test_independently_generated_signature(self):
        result = verify(self.image, 0x60000000, 32)
        self.assertTrue(result["signatures"][0]["rsa_signature_valid"])

    def test_changed_authenticated_byte_rejected(self):
        image = bytearray(self.image)
        image[0] ^= 1
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify(bytes(image), 0x60000000, 32)

    def test_truncated_signature_rejected(self):
        with self.assertRaises(ValueError):
            verify(self.image[:-20], 0x60000000, 32)

    def test_changed_signature_rejected(self):
        image = bytearray(self.image)
        image[-1] ^= 1
        with self.assertRaises(InvalidSignature):
            verify(bytes(image), 0x60000000, 32)

    def test_address_alias_is_explicit(self):
        with self.assertRaises(ValueError):
            verify(self.image, 0x60800000, 32)
        self.assertTrue(verify(self.image, 0x60800000, 32,
                               [(0x60000000, 0, 32)])["signatures"][0]["digest_matches"])

    def test_csf_zero_length_command_rejected(self):
        image = bytearray(self.image)
        image[37:39] = b"\0\0"
        with self.assertRaisesRegex(ValueError, "command size"):
            verify(bytes(image), 0x60000000, 32)

    def test_arithmetic_witness(self):
        args = (0x60000000, 0x60FFFFFF, 0x60000010, 0xFFFFFFF8)
        self.assertTrue(observed_range_check(*args))
        self.assertFalse(nonwrapping_range_check(*args))

    def test_normal_range_boundaries(self):
        self.assertTrue(nonwrapping_range_check(0, 255, 0, 256))
        self.assertFalse(nonwrapping_range_check(0, 255, 0, 257))
        self.assertFalse(nonwrapping_range_check(0, 255, 1, 0))


if __name__ == "__main__":
    unittest.main()
