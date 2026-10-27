"""Compile pinned upstream bridge.c for host-side synthetic input experiments.

The actual upstream C is compiled separately with tiny FreeRTOS queue stubs;
this does not execute BLE, ESP-IDF, queues or physical USB. USB captures are
used as hypothetical BLE-shaped test vectors, not evidence of BLE contents.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tools.prepare_external_bridge import verify_checkout, MANIFEST

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'tests/fixtures/phase84'
FLAGS=('assistant','capture','rs','options','menu','stadia','a','b','x','y','lb','rb','ls')


def verify_headers(checkout, commit):
    hashes={}
    for name in ('main/bridge.h','main/dongle_config.h','main/dongle_state.h'):
        expected=subprocess.run(['git','-C',str(checkout),'show',f'{commit}:{name}'],check=True,capture_output=True).stdout
        actual=(checkout/name).read_bytes()
        if actual!=expected:
            raise ValueError('Upstream header differs from pinned Git object: '+name)
        hashes[name]=hashlib.sha256(actual).hexdigest()
    return hashes


def build(checkout, output):
    manifest=json.loads(MANIFEST.read_text(encoding='utf-8'))
    verification=verify_checkout(checkout,manifest)
    headers=verify_headers(checkout,manifest['commit'])
    version=subprocess.run([sys.executable,'-m','ziglang','version'],check=True,capture_output=True,text=True).stdout.strip()
    if version!='0.13.0':raise ValueError('ziglang 0.13.0 required for recorded host build')
    command=[sys.executable,'-m','ziglang','cc','-O2','-shared',
             '-I',str(FIXTURES),'-I',str(checkout/'main'),
             str(checkout/'main/bridge.c'),str(FIXTURES/'host_wrapper.c'),'-o',str(output)]
    subprocess.run(command,check=True,capture_output=True)
    return verification,headers,version


class Bridge:
    def __init__(self, path):
        self.lib=ctypes.CDLL(str(path.resolve()))
        pointer=ctypes.POINTER(ctypes.c_uint8)
        self.lib.test_translate.argtypes=(pointer,pointer)
        self.lib.test_translate.restype=None
        self.lib.test_parse_flags.argtypes=(pointer,ctypes.c_size_t,pointer)
        self.lib.test_parse_flags.restype=None

    def run(self, payload):
        if len(payload)!=10:raise ValueError('Ten-byte synthetic vector required')
        source=(ctypes.c_uint8*10).from_buffer_copy(payload)
        xbox=(ctypes.c_uint8*20)()
        flags=(ctypes.c_uint8*len(FLAGS))()
        self.lib.test_translate(source,xbox)
        self.lib.test_parse_flags(source,len(payload),flags)
        return bytes(xbox),dict(zip(FLAGS,flags))


def run_cases(bridge, capture):
    if type(capture['report_count']) is not int or capture['report_count']<0:
        raise ValueError('Capture total must be a nonnegative integer')
    neutral=bytes.fromhex('08000080808080000000')
    baseline,baseflags=bridge.run(neutral)
    rows=[]
    for byte in (1,2,9):
        for bit in range(8):
            changed=bytearray(neutral)
            changed[byte]^=1<<bit
            output,flags=bridge.run(changed)
            rows.append({'payload_byte':byte,'bit':bit,
                         'changed_output_bytes':[i for i,(a,b) in enumerate(zip(baseline,output)) if a!=b],
                         'changed_parsed_flags':[key for key in FLAGS if flags[key]!=baseflags[key]]})
    for (byte,bit) in ((1,2),(1,3),(9,0),(9,1),(9,2)):
        row=next(x for x in rows if (x['payload_byte'],x['bit'])==(byte,bit))
        if row['changed_output_bytes'] or row['changed_parsed_flags']:
            raise ValueError('Unexpected changed output/semantic flag for target bit')
    pair_checks=0
    weighted_pairs=0
    for row in capture['distinct_reports']:
        count=row['count']
        report=bytes.fromhex(row['hex'])
        if len(report)!=11 or report[0]!=3 or type(count)!=int or count<=0:
            raise ValueError('Invalid source capture record')
        payload=report[1:]
        original=bridge.run(payload)
        for byte,bit in ((1,2),(1,3),(9,0),(9,1),(9,2)):
            changed=bytearray(payload)
            changed[byte]^=1<<bit
            if bridge.run(changed)!=original:
                raise ValueError('Expected paired vectors to preserve output and selected flags')
            pair_checks+=1
            weighted_pairs+=count
    if sum(row['count'] for row in capture['distinct_reports'])!=capture['report_count']:
        raise ValueError('Capture count mismatch')
    return {'phase':84,'compiler':'ziglang 0.13.0 host cc -O2',
            'baseline_input':neutral.hex(),'baseline_xbox_bytes':baseline.hex(),
            'individual_bit_cases':rows,
            'usb_capture_phase':capture['phase'],
            'usb_capture_canonical_sha256':hashlib.sha256(json.dumps(capture,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest(),
            'usb_capture_report_count':capture['report_count'],
            'distinct_usb_payloads':len(capture['distinct_reports']),
            'hypothetical_usb_as_ble_paired_checks':pair_checks,
            'hypothetical_usb_as_ble_weighted_pairs':weighted_pairs,
            'paired_bit_positions':[[1,2],[1,3],[9,0],[9,1],[9,2]],
            'limits':['Host compilation of original bridge.c with stubbed queues, not ESP32 firmware.',
                      'The 13 parsed flags exclude raw report storage and all other state fields.',
                      'USB payloads replayed as hypothetical BLE inputs; actual BLE equivalence is unproven.',
                      'No queue scheduling, button action execution, device I/O or console compatibility tested.']}


def audit(checkout, library, capture):
    verified,headers,version=build(checkout,library)
    result=run_cases(Bridge(library),capture)
    result.update({'upstream_commit':verified['commit'],
                   'upstream_bridge_sha256':verified['sha256']['main/bridge.c'],
                   'upstream_header_sha256':headers,'compiler_version':version})
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('checkout',type=Path)
    p.add_argument('capture',type=Path)
    p.add_argument('--library',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=audit(args.checkout.resolve(),args.library.resolve(),json.loads(args.capture.read_text()))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
