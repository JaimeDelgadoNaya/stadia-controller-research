"""Build a *synthetic* ARM Cortex-M7 RAM self-test. Never a Stadia update."""
from pathlib import Path
import json
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build'/'arm'
def run(cmd):
    result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    if result.returncode:
        raise RuntimeError(f"{cmd} failed: {result.stderr}")
    return result.stdout
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    flags=['clang','--target=arm-none-eabi','-mcpu=cortex-m7','-mthumb',
           '-mfloat-abi=soft','-ffreestanding','-fno-builtin','-std=c11',
           '-Os','-Wall','-Wextra','-Werror','-fdata-sections','-ffunction-sections']
    include=['-I'+str(ROOT/'firmware'),'-I'+str(ROOT/'firmware_codec'),
             '-I'+str(ROOT/'tools/arm_phase108_headers')]
    source=[ROOT/'firmware/startup_ram_probe.S',ROOT/'firmware/ram_probe.c',
            ROOT/'firmware/stadia_rt1061_inputs.c',
            ROOT/'firmware_codec/stadia_xusb_codec.c',
            ROOT/'firmware/memset_freestanding.c']
    objects=[]
    for src in source:
        obj=OUT/(src.name.replace('.S','.o').replace('.c','.o'))
        run(flags+include+['-c',str(src),'-o',str(obj)])
        objects.append(obj)
    elf=OUT/'stadia_ram_codec_selftest.elf'
    run(['clang','--target=arm-none-eabi','-mcpu=cortex-m7','-mthumb',
         '-mfloat-abi=soft','-nostdlib','-fuse-ld=lld','-Wl,--gc-sections',
         '-Wl,-T,'+str(ROOT/'firmware/ram_probe.ld'),
         '-Wl,-Map,'+str(OUT/'link.map'),*map(str,objects),'-o',str(elf)])
    hdr=run(['readelf','-h',str(elf)])
    sections=run(['readelf','-SW',str(elf)])
    symbols=run(['readelf','-sW',str(elf)])
    if 'Machine:                           ARM' not in hdr: raise AssertionError('non ARM')
    if 'Type:                              EXEC' not in hdr: raise AssertionError('non ELF EXEC')
    entry=int(hdr.split('Entry point address:')[1].splitlines()[0].strip(),16)
    assert entry&1 and 0x20200000<=entry<0x20220000
    for name in ('Reset_Handler','stadia_usb_dma_staging',
                 'stadia_rt1061_build_xusb','stadia_xusb_from_bruce_raw'):
        assert name in symbols,name
    dma=next(x for x in sections.splitlines() if ' .usb_dma ' in x)
    fields=dma.split();index=fields.index('.usb_dma')
    addr=int(fields[index+2],16)
    assert addr%64==0 and 0x20200000<=addr<0x20220000
    proof={'kind':'synthetic ARM RAM diagnostic ELF, not installable firmware',
           'elf':str(elf),'bytes':elf.stat().st_size,'entry':hex(entry),
           'dma_section':hex(addr),'dma_in_ocram':True,
           'bootrom_exploit':False,'hab_bypass':False,'usb_physical':False,
           'xinput_windows_driver':False,'wrote_flash_or_fuses':False,
           'hardware_execution':'NOT TESTED'}
    (OUT/'evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof,indent=2))
if __name__=='__main__':
    main()
