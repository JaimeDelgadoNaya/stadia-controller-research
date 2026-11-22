"""Offline C + ARM proof gates. No USB, ROM or physical device contact."""
from pathlib import Path
import subprocess, tempfile, unittest, shutil, json, hashlib
ROOT=Path(__file__).resolve().parents[1]
def present():
 return all(shutil.which(x) for x in ['clang','ld.lld','cc','readelf'])
@unittest.skipUnless(present(),'Requires clang/lld/cc/readelf host toolchain')
class Phase108Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  subprocess.run(['python',str(ROOT/'tools/build_ram_probe.py')],check=True,capture_output=True,text=True)
  cls.elf=ROOT/'build/arm/stadia_ram_codec_selftest.elf'
  cls.hdr=subprocess.check_output(['readelf','-h',str(cls.elf)],text=True)
  cls.sec=subprocess.check_output(['readelf','-SW',str(cls.elf)],text=True)
  cls.syms=subprocess.check_output(['readelf','-sW',str(cls.elf)],text=True)
 def test_native_c_with_ubsan(self):
  with tempfile.TemporaryDirectory() as td:
   exe=Path(td)/'testboard'
   cmd=['cc','-std=c11','-Wall','-Wextra','-Werror','-pedantic',
    '-fsanitize=undefined','-fno-sanitize-recover=all',
    '-I'+str(ROOT/'firmware'),'-I'+str(ROOT/'firmware_codec'),
    str(ROOT/'tests/test_rt1061_inputs.c'),
    str(ROOT/'firmware/stadia_rt1061_inputs.c'),
    str(ROOT/'firmware_codec/stadia_xusb_codec.c'),
    str(ROOT/'firmware_codec/stadia_xusb_transport.c'),'-o',str(exe)]
   subprocess.run(cmd,check=True,capture_output=True,text=True)
   self.assertIn('passed',subprocess.check_output([str(exe)],text=True))
 def test_arm_machine(self):
  self.assertIn('Machine:                           ARM',self.hdr)
 def test_elf_executable_but_not_stadia_image(self):
  self.assertIn('Type:                              EXEC',self.hdr)
  entry=int(self.hdr.split('Entry point address:')[1].splitlines()[0].strip(),16)
  self.assertTrue(entry&1)
  self.assertTrue(0x20200000<=entry<0x20220000)
 def test_codec_symbols(self):
  for v in ['Reset_Handler','stadia_rt1061_build_xusb',
            'stadia_xusb_from_bruce_raw','stadia_ram_probe_result']:
   self.assertIn(v,self.syms)
 def test_dma_staging_ocrambased_and_aligned(self):
  row=next(x for x in self.sec.splitlines() if ' .usb_dma ' in x)
  fields=row.split();addr=int(fields[fields.index('.usb_dma')+2],16)
  self.assertTrue(0x20200000<=addr<0x20220000)
  self.assertEqual(addr%64,0)
  self.assertIn('NOBITS',row)
 def test_hall_precondition(self):
  c=(ROOT/'firmware/stadia_rt1061_inputs.c').read_text()
  self.assertIn('hall_power_enabled',c)
  self.assertIn('normalize_trigger',c)
  self.assertIn('STADIA_RT1061_HALL_NOT_POWERED',c)
 def test_reproducible_elf(self):
  old=hashlib.sha256(self.elf.read_bytes()).hexdigest()
  subprocess.run(['python',str(ROOT/'tools/build_ram_probe.py')],check=True,capture_output=True,text=True)
  self.assertEqual(old,hashlib.sha256(self.elf.read_bytes()).hexdigest())
 def test_no_physical_execution_claim(self):
  d=json.loads((ROOT/'build/arm/evidence.json').read_text())
  self.assertFalse(d['bootrom_exploit'])
  self.assertFalse(d['hab_bypass'])
  self.assertFalse(d['usb_physical'])
  self.assertFalse(d['xinput_windows_driver'])
  self.assertFalse(d['wrote_flash_or_fuses'])
if __name__=='__main__':unittest.main()
