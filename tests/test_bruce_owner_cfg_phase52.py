"""Phase52 bounded interprocedural branch and pointer-transfer regressions."""
import unittest
from tools import audit_bruce_owner_cfg_phase52 as a

def ins(pc,m,op,nxt):
    return {"pc":pc,"m":m,"op":op,"next":nxt}

class OwnerCFG52(unittest.TestCase):
    def test_mode2_conditional_interprocedural_pointer_transfer(self):
        code={
          0x60060fe8:ins(0x60060fe8,"b","#0x60061020",None),
          0x60061020:ins(0x60061020,"cmp","r1, #2",0x6006102a),
          0x6006102a:ins(0x6006102a,"bne","#0x60061080",0x6006102c),
          0x6006102c:ins(0x6006102c,"mov","r0, r0",0x6006102e),
          0x6006102e:ins(0x6006102e,"bl","#0x60060f84",0x60061032),
          0x60061032:ins(0x60061032,"pop","{pc}",None),
          0x60060f84:ins(0x60060f84,"adds","r1, r0, #4",0x60060f86),
          0x60060f86:ins(0x60060f86,"bl","#0x600550e4",0x60060f8a),
          0x60060f8a:ins(0x60060f8a,"pop","{pc}",None),
          0x600550e4:ins(0x600550e4,"mov","r4, r1",0x600550e6),
          0x600550e6:ins(0x600550e6,"mov.w","r5, #0x20004080",0x600550e8),
          0x600550e8:ins(0x600550e8,"str","r4, [r5, #4]",0x600550ea),
          0x600550ea:ins(0x600550ea,"pop","{pc}",None),
        }
        yes=a.flow(code,b"",2)
        self.assertEqual(len(yes["conditional_store_candidates"]),1)
        store=yes["conditional_store_candidates"][0]
        self.assertEqual(store["address"],hex(a.CONFIG_SLOT))
        self.assertEqual(store["source"],hex(a.OWNER+4))
        self.assertEqual(store["call_chain"],
                         ["0x60060fe8","owner_constructor","shared_config_constructor"])
        no=a.flow(code,b"",1)
        self.assertEqual(no["conditional_store_candidates"],[])

    def test_reg_reassigned_does_not_preserve_owner_pointer(self):
        code={
          0x60060fe8:ins(0x60060fe8,"mov","r4, r0",0x60060feA),
          0x60060feA:ins(0x60060feA,"ldr","r4, [r3]",0x60060fec),
          0x60060fec:ins(0x60060fec,"str","r1, [r4, #4]",0x60060fee),
          0x60060fee:ins(0x60060fee,"pop","{pc}",None),
        }
        self.assertEqual(a.flow(code,b"",2)["conditional_store_candidates"],[])

    def test_external_call_clobbers_caller_saved_r1(self):
        code={
          0x60060fe8:ins(0x60060fe8,"bl","#0x600d1066",0x60060fec),
          0x60060fec:ins(0x60060fec,"cmp","r1, #2",0x60060fee),
          0x60060fee:ins(0x60060fee,"pop","{pc}",None),
        }
        x=a.flow(code,b"",2)
        self.assertEqual(x["conditional_store_candidates"],[])
        self.assertGreater(x["scanned_states"],0)

    def test_fail_on_insufficient_search_budget(self):
        code={0x60060fe8:ins(0x60060fe8,"b","#0x60061020",None),
              0x60061020:ins(0x60061020,"pop","{pc}",None)}
        with self.assertRaisesRegex(ValueError,"budget"):
            a.flow(code,b"",2,max_states=1)

    def test_signed_image_not_synthetic(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            a.audit(b"synthetic")
if __name__=="__main__":unittest.main()
