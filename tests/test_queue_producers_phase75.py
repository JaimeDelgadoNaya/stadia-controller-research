"""Phase 75 queue producer candidate provenance and fail-closed tests."""
import struct
import unittest
from tools import audit_queue_producers_phase75 as a

class WorkQueueProducersTests(unittest.TestCase):
    def test_known_queue_address_relationship(self):
        self.assertEqual(a.QUEUE,0x2002014C)
        self.assertEqual(a.CONTROL_FIELD,0x200201FC)
        self.assertEqual(a.QUEUE_RECEIVER,0x6013D268)

    def test_word_boundary(self):
        payload=bytearray(0x60)
        struct.pack_into("<I",payload,0x20,a.QUEUE)
        self.assertEqual(a.signed_word(payload,0x20),a.QUEUE)
        for offset in [-4,3,0x60]:
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError,"aligned"):
                    a.signed_word(payload,offset)

    def test_synthetic_literals_not_runtime_proof(self):
        image=bytearray(0x100)
        struct.pack_into("<I",image,0x20,a.QUEUE)
        struct.pack_into("<I",image,0x24,a.CONTROL_FIELD)
        r=a.queue_literals(image)
        self.assertEqual([x["value"] for x in r],
                         [hex(a.QUEUE),hex(a.CONTROL_FIELD)])
        self.assertTrue(all(x["domain"]=="XIP_OR_DATA" for x in r))

    def test_thumb_pc_relative_load_synthetic(self):
        image=bytearray(0x100)
        # At XIP offset 0x1c PC literal is 0x20: LDR r0,[PC,#0].
        struct.pack_into("<H",image,0x1c,0x4800)
        struct.pack_into("<I",image,0x20,a.QUEUE)
        hits=a.pc_literal_load_candidates(image,a.queue_literals(image),prior=0x40)
        self.assertTrue(any(x["pc"]==hex(a.BASE+0x1c) and
                            x["loaded_word"]==hex(a.QUEUE) for x in hits))
        self.assertTrue(all(x["reachable"]=="UNVERIFIED" for x in hits))

    def test_original_signed_sample_required(self):
        with self.assertRaisesRegex(ValueError,"SHA-pinned"):
            a.audit(b"invalid unsigned bytes")

    def test_ITCM_bounds_not_deduced_from_RAM(self):
        self.assertGreater(a.ITCM_LENGTH,0x7734)
        self.assertNotIn(a.QUEUE,a.ITCM_KNOWN_CALL_TARGETS)


if __name__=="__main__":
    unittest.main()
