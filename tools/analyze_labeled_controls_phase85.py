"""Analyze user-confirmed, separately captured USB HID control trials offline."""
import argparse
import hashlib
import json
from pathlib import Path
from tools.decode_hid_input_phase81 import decode_report, DESCRIPTOR_SHA256

BUTTON_ACTIONS=('A','B','X','Y')
HAT_ACTIONS=('dpad_up','dpad_right','dpad_down','dpad_left')
TRIGGER_ACTIONS=('LT','RT')


def analyze(source, descriptor, bridge_comparison):
    if hashlib.sha256(descriptor).hexdigest()!=DESCRIPTOR_SHA256:
        raise ValueError('Recorded descriptor SHA-256 required')
    actions={}
    for trial in source['trials']:
        name=trial['interaction']['requested_action']
        if name in actions or trial['interaction']['actual_action_confirmation']!='user_confirmed_only_requested_action':
            raise ValueError('Duplicate or unconfirmed trial')
        if type(trial['report_count']) is not int or trial['report_count']<=0:
            raise ValueError('Positive integer report count required')
        states=[]
        for row in trial['distinct_reports']:
            if type(row['count']) is not int or row['count']<=0:
                raise ValueError('Positive integer frequency required')
            state=decode_report(bytes.fromhex(row['hex']),descriptor)
            if state['nonzero_constant_padding'] or state['generic_axes_outside_logical_range']:
                raise ValueError('Unexpected padding or analog axis value')
            states.append((state,row['count']))
        if sum(n for _,n in states)!=trial['report_count']:
            raise ValueError('Report count mismatch')
        button_sets={tuple(s['button_usages']) for s,_ in states}
        hats={s['hat_raw'] for s,_ in states}
        consumer={tuple(s['consumer_usages']) for s,_ in states}
        fields=('X','Y','Z','Rz','0xc5','0xc4')
        observed={key:sorted({(s['axes']|s['page2_values'])[key] for s,_ in states}) for key in fields}
        varied=[key for key in fields if len(observed[key])>1]
        if consumer!={()}:
            raise ValueError('Unexpected consumer control')
        base={'report_count':trial['report_count'],'distinct_reports':len(states),
              'user_confirmed':True,'unchanged_analog_fields':{k:v[0] for k,v in observed.items() if len(v)==1}}
        if name in BUTTON_ACTIONS:
            active=button_sets-{()}
            if len(active)!=1 or () not in button_sets or len(next(iter(active)))!=1 or hats!={8} or varied:
                raise ValueError('Button trial is not isolated with press/release')
            base['usb_button_usage']=next(iter(active))[0]
        elif name in HAT_ACTIONS:
            if button_sets!={()} or varied or 8 not in hats or len(hats)!=2:
                raise ValueError('Hat trial is not isolated with press/release')
            base['hat_direction_code']=next(iter(hats-{8}))
            base['hat_released_code']=8
        elif name in TRIGGER_ACTIONS:
            active=button_sets-{()}
            if len(active)!=1 or () not in button_sets or len(next(iter(active)))!=1 or hats!={8} or len(varied)!=1:
                raise ValueError('Trigger trial is not isolated')
            usage=next(iter(active))[0]
            key=varied[0]
            groups={0:[],1:[]}
            for state,_ in states:
                flag=int(usage in state['button_usages'])
                groups[flag].append((state['axes']|state['page2_values'])[key])
            base.update({'usb_analog_usage':key,'usb_button_usage':usage,
                         'analog_min':min(observed[key]),'analog_max':max(observed[key]),
                         'distinct_analog_values':len(observed[key]),
                         'sampled_analog_64':64 in observed[key],
                         'analog_range_button_clear':[min(groups[0]),max(groups[0])],
                         'analog_range_button_set':[min(groups[1]),max(groups[1])],
                         'all_samples_match_candidate_boundary_64':all((v>=64)==bool(flag) for flag,values in groups.items() for v in values)})
        else:
            raise ValueError('Unexpected action')
        actions[name]=base
    if set(actions)!=set(BUTTON_ACTIONS+HAT_ACTIONS+TRIGGER_ACTIONS):
        raise ValueError('Expected exactly the ten confirmed trials')
    bridge_buttons={x['upstream_ble_label']:x['usb_button_usage'] for x in bridge_comparison['matched_button_positions']}
    bridge_analog={x['upstream_ble_label']:hex(x['usb_usage']) for x in bridge_comparison['matched_analog_positions'] if x['usb_usage_page']==2}
    matches={name:actions[name]['usb_button_usage']==bridge_buttons[name.lower()] for name in BUTTON_ACTIONS}
    matches.update({name:actions[name]['usb_analog_usage']==bridge_analog[name.lower()] for name in TRIGGER_ACTIONS})
    return {'phase':85,'descriptor_sha256':DESCRIPTOR_SHA256,
            'trial_count':len(actions),'user_confirmed_trial_count':len(actions),
            'trials':actions,'corresponding_upstream_ble_position_matches_usb_observation':matches,
            'limits':['User-confirmed actions in this USB session only; no physical BLE labels established.',
                      'Aggregate reports have no temporal order; counts are not press counts.',
                      'A threshold candidate is only supported at sampled values; no hysteresis or exact boundary proven.',
                      'No bridge hardware, USB output reports, firmware changes or console behavior tested.']}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('descriptor',type=Path)
    p.add_argument('bridge_comparison',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    result=analyze(json.loads(args.capture.read_text()),bytes.fromhex(json.loads(args.descriptor.read_text())['descriptor_hex']),json.loads(args.bridge_comparison.read_text()))
    args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
