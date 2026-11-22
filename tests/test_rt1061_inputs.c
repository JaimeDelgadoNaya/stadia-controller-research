#include "../firmware/stadia_rt1061_inputs.h"
#include "../firmware_codec/stadia_xusb_transport.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static const stadia_rt1061_calibration cal={1734,578,1747,616};
static stadia_rt1061_sample neutral(void){
 stadia_rt1061_sample s={0};
 s.hall_power_enabled=1;
 s.adc1[8]=1747;s.adc1[13]=1734;
 s.adc1[9]=s.adc1[10]=s.adc1[11]=s.adc1[12]=2048;
 return s;
}
static unsigned mask(const uint8_t *p){return p[2]|((unsigned)p[3]<<8);}
static unsigned get32(const uint8_t *p){return p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24);}
int main(void){
 const unsigned buttons[17]={1,2,4,8,0x1000,0x2000,0x4000,0x8000,
  0x0400,0x0020,0x0010,0,0,0x0040,0x0080,0x0100,0x0200};
 stadia_rt1061_sample s=neutral();
 stadia_xusb_transport transport;
 uint8_t p[20],raw[STADIA_RT1061_RAW_LENGTH],queued[20];
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0);
 assert(mask(p)==0 && p[1]==20 && p[4]==0 && p[5]==0);
 for(unsigned i=0;i<17;i++){
  s=neutral();s.pressed_mask=1u<<i;
  assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0);
  assert(mask(p)==buttons[i]);
 }
 s=neutral();s.pressed_mask=1|2|4|8;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0&&mask(p)==0);
 s=neutral();s.adc1[13]=578;s.adc1[8]=616;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0&&p[4]==255&&p[5]==255);
 s.adc1[13]=1156;s.adc1[8]=1182;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0&&p[4]>0&&p[4]<255&&p[5]>0&&p[5]<255);
 s=neutral();s.adc1[11]=0;s.adc1[12]=4095;
 assert(stadia_rt1061_build_raw(&s,&cal,raw)==0);
 assert(get32(raw+0x1c)==0&&get32(raw+0x20)==4095);
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0&&p[6]==0&&p[7]==0x80);
 memset(p,0xa5,sizeof(p));s.hall_power_enabled=0;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==STADIA_RT1061_HALL_NOT_POWERED);
 for(unsigned i=0;i<20;i++)assert(p[i]==0xa5);
 s=neutral();s.adc1[9]=4096;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==STADIA_RT1061_BAD_INPUT);
 s=neutral();s.pressed_mask=1u<<19;
 assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==STADIA_RT1061_BAD_INPUT);
 s=neutral();stadia_rt1061_calibration bad=cal;bad.left_full=bad.left_rest;
 assert(stadia_rt1061_build_raw(&s,&bad,raw)==STADIA_RT1061_BAD_CALIBRATION);
 assert(stadia_rt1061_build_raw(NULL,&cal,raw)==STADIA_RT1061_BAD_INPUT);
 assert(stadia_rt1061_build_xusb(&s,&cal,p,2)==STADIA_RT1061_BAD_INPUT);
 s.pressed_mask=1u<<4;
 assert(stadia_rt1061_build_raw(&s,&cal,raw)==0);
 stadia_xusb_transport_init(&transport);
 stadia_xusb_transport_set_configured(&transport,1);
 assert(stadia_xusb_transport_queue_raw(&transport,raw,sizeof(raw),0)==0);
 assert(stadia_xusb_transport_acquire_in(&transport,queued)==0);
 assert(mask(queued)==0x1000&&queued[1]==20);
 assert(stadia_xusb_transport_finish_in(&transport,1)==0);
 int prev=-1;
 for(int a=1734;a>=578;--a){
  s.adc1[13]=(uint16_t)a;
  assert(stadia_rt1061_build_xusb(&s,&cal,p,0)==0);
  assert((int)p[4]>=prev);prev=p[4];
 }
 assert(prev==255);
 puts("RT1061 snapshot and Xbox XUSB offline tests passed");
 return 0;
}
