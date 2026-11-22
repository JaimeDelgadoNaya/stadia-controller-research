#include "stadia_rt1061_inputs.h"
#include "stadia_xusb_codec.h"
#include <string.h>
static void little_u32(uint8_t *out,uint32_t v) {
 out[0]=(uint8_t)v;out[1]=(uint8_t)(v>>8);
 out[2]=(uint8_t)(v>>16);out[3]=(uint8_t)(v>>24);
}
static unsigned pressed(uint32_t mask,unsigned i) {
 return (unsigned)((mask>>i)&1u);
}
static uint32_t normalize_trigger(uint16_t v,uint16_t rest,uint16_t full) {
 if(v>=rest)return 0;
 if(v<=full)return 4096;
 return ((uint32_t)(rest-v)*4096u+(uint32_t)(rest-full)/2u)/(uint32_t)(rest-full);
}
int stadia_rt1061_build_raw(const stadia_rt1061_sample *s,
                           const stadia_rt1061_calibration *c,
                           uint8_t raw[STADIA_RT1061_RAW_LENGTH]) {
 uint8_t r[STADIA_RT1061_RAW_LENGTH];
 if(!s||!c||!raw||(s->pressed_mask&~0x1ffffu))return STADIA_RT1061_BAD_INPUT;
 if(!s->hall_power_enabled)return STADIA_RT1061_HALL_NOT_POWERED;
 if(c->left_full>=c->left_rest||c->right_full>=c->right_rest||
    c->left_rest>4095||c->right_rest>4095)return STADIA_RT1061_BAD_CALIBRATION;
 for(unsigned i=8;i<=13;i++)if(s->adc1[i]>4095)return STADIA_RT1061_BAD_INPUT;
 memset(r,0,sizeof(r));
 r[0x08]=pressed(s->pressed_mask,4); /* A */
 r[0x09]=pressed(s->pressed_mask,5); /* B */
 r[0x0a]=pressed(s->pressed_mask,6); /* X */
 r[0x0b]=pressed(s->pressed_mask,7); /* Y */
 r[0x0c]=pressed(s->pressed_mask,0); /* Up */
 r[0x0d]=pressed(s->pressed_mask,1); /* Down */
 r[0x0e]=pressed(s->pressed_mask,2); /* Left */
 r[0x0f]=pressed(s->pressed_mask,3); /* Right */
 r[0x10]=pressed(s->pressed_mask,15); /* L1 */
 r[0x11]=pressed(s->pressed_mask,16); /* R1 */
 r[0x14]=pressed(s->pressed_mask,13); /* L3 */
 r[0x15]=pressed(s->pressed_mask,14); /* R3 */
 r[0x16]=pressed(s->pressed_mask,9); /* Options -> Back */
 r[0x17]=pressed(s->pressed_mask,10); /* Menu -> Start */
 r[0x1a]=pressed(s->pressed_mask,8); /* Stadia -> Guide */
 /* Assistant and Capture have no directly equivalent Xbox 360 bit. */
 little_u32(r+0x1c,s->adc1[11]); /* LX */
 little_u32(r+0x20,s->adc1[12]); /* LY */
 little_u32(r+0x24,s->adc1[9]); /* RX */
 little_u32(r+0x28,s->adc1[10]); /* RY */
 little_u32(r+0x2c,normalize_trigger(s->adc1[13],c->left_rest,c->left_full));
 little_u32(r+0x30,normalize_trigger(s->adc1[8],c->right_rest,c->right_full));
 memcpy(raw,r,sizeof(r));return STADIA_RT1061_OK;
}
int stadia_rt1061_build_xusb(const stadia_rt1061_sample *s,
                            const stadia_rt1061_calibration *c,
                            uint8_t out[20],int invert_y) {
 uint8_t raw[STADIA_RT1061_RAW_LENGTH];
 if(!out||(invert_y!=0&&invert_y!=1))return STADIA_RT1061_BAD_INPUT;
 int result=stadia_rt1061_build_raw(s,c,raw);
 if(result!=STADIA_RT1061_OK)return result;
 return stadia_xusb_from_bruce_raw(raw,sizeof(raw),out,invert_y);
}
