"""Synthetic, offline tests for the pinned archived WebHID/USB updater audit."""
import unittest
from tools import audit_archived_updater as m


def fixture():
    # Deliberately inert text: NEVER eval() or execute JavaScript.
    blocks=[]
    for name,anchors in m.FUNCTION_ANCHORS.items():
        blocks.append("function "+name+"(a){"+(";".join(anchors))+";}")
    blocks.extend(m.GLOBAL_ANCHORS)
    return "\n".join(blocks).encode("utf-8")


def synthetic_audit(data):
    return m.audit(data,expected_blob=m.git_blob_sha1(data),
                   expected_size=len(data))


class ArchivedUpdaterAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=fixture()

    def test_locked_source_rejects_synthetic(self):
        with self.assertRaisesRegex(ValueError,"size mismatch"):
            m.audit(self.source)

    def test_blob_identity_is_git_blob_sha1_not_raw_bytes(self):
        self.assertEqual(len(m.SOURCE_BLOB_SHA1),40)
        self.assertNotEqual(m.git_blob_sha1(b"abc"),
                            __import__("hashlib").sha1(b"abc").hexdigest())

    def test_archived_original_metadata_is_pinned(self):
        self.assertEqual(m.SOURCE_BYTES,149810)
        self.assertIn("hazrpg/stadia-flasher",m.SOURCE_URL)

    def test_synthetic_audit_has_four_distinct_modes(self):
        got=synthetic_audit(self.source)
        self.assertEqual([x["pid"] for x in got["modes"]],
                         ["0x9400","0x946b","0x0135","0x0073"])
        self.assertEqual(got["transfer_calls"]["webhid_send_report"],4)

    def test_no_archived_webusb_bulk_install(self):
        got=synthetic_audit(self.source)
        self.assertEqual(got["transfer_calls"]["webusb_bulk_out"],0)
        self.assertEqual(got["transfer_calls"]["webusb_bulk_in"],0)
        self.assertEqual(got["cross_artifact"] if "cross_artifact" in got else
                         got["critical_distinctions"]["bootloader_A_bulk_OUT_0x07"],
                         "NOT used as a flash data endpoint by this archived host script")

    def test_class_control_requests_are_not_update_data(self):
        stages=synthetic_audit(self.source)["host_to_receiver_matrix"]
        self.assertIn("0x81",stages[0]["host"])
        self.assertIn("0x83",stages[1]["host"])
        self.assertIn("0x84",stages[1]["host"])
        self.assertEqual(stages[0]["mode"],"normal")

    def test_rom_sdp_report_protocol_is_distinct_from_flashloader(self):
        mtx=synthetic_audit(self.source)["host_to_receiver_matrix"]
        self.assertEqual(mtx[2]["mode"],"rom_sdp")
        self.assertIn("0x0404",mtx[2]["host"])
        self.assertIn("0x0b0b",mtx[2]["host"])
        self.assertEqual(mtx[3]["mode"],"signed_ram_flashloader")

    def test_ram_loader_erase_and_data_chunk_limits_are_described(self):
        mtx=synthetic_audit(self.source)["host_to_receiver_matrix"]
        self.assertIn("16 KiB",mtx[5]["host"])
        self.assertIn("512-byte",mtx[5]["host"])
        self.assertIn("0x0b",mtx[5]["host"])

    def test_metadata_is_not_crypto_validation(self):
        report=synthetic_audit(self.source)
        self.assertIn("NOT cryptographic",report["host_to_receiver_matrix"][4]["checks"])
        self.assertIn("not signature validation",
                      report["critical_distinctions"]["host_image_metadata"])

    def test_unsigned_custom_execution_unproven(self):
        r=synthetic_audit(self.source)
        self.assertEqual(r["decision"]["firmware_unsigned_custom_execution"],
                         "NOT DEMONSTRATED")
        self.assertEqual(r["decision"]["recoverable_custom_execution"],
                         "NOT DEMONSTRATED")
        self.assertFalse(r["hardware_access"])

    def test_removing_rom_write_command_rejected(self):
        txt=self.source.decode().replace("P:1028,address:536870912","P:7,address:536870912")
        with self.assertRaisesRegex(ValueError,"bj anchor"):
            synthetic_audit(txt.encode())

    def test_removing_writememory_rejected(self):
        txt=self.source.decode().replace("P:4,flags:1","P:8,flags:1")
        with self.assertRaisesRegex(ValueError,"nj anchor"):
            synthetic_audit(txt.encode())

    def test_code_shift_without_signature_should_fail_pin(self):
        altered=self.source+b"\n"
        with self.assertRaisesRegex(ValueError,"SHA-1 mismatch"):
            m.audit(altered,expected_size=len(altered),
                    expected_blob=m.git_blob_sha1(self.source))

    def test_unexpected_bulk_transfer_rejected(self):
        txt=self.source+b"\n// unexpected .transferOut("
        with self.assertRaisesRegex(ValueError,"callsite inventory"):
            synthetic_audit(txt)

    def test_unexpected_second_control_request_rejected(self):
        txt=self.source+b"\n// extra .controlTransferIn("
        with self.assertRaisesRegex(ValueError,"callsite inventory"):
            synthetic_audit(txt)

    def test_literal_filter_must_be_present(self):
        txt=self.source.decode().replace("vendorId:8137,productId:309",
                                          "vendorId:8137,productId:308")
        with self.assertRaisesRegex(ValueError,"global anchor"):
            synthetic_audit(txt.encode())

    def test_report_does_not_expose_flash_execute_actions(self):
        r=synthetic_audit(self.source)
        self.assertFalse(r["javascript_executed"])
        self.assertFalse(r["usb_transfers"])
        self.assertFalse(r["flash_writes"])
        self.assertIn("package_B",r["decision"])

    def test_non_utf8_source_rejected(self):
        data=self.source+b"\xff"
        with self.assertRaisesRegex(ValueError,"UTF-8"):
            synthetic_audit(data)


if __name__=="__main__":
    unittest.main()
