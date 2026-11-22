#include "stadia_xusb_codec.h"
#include <string.h>

/* Portable and allocation-free; only writes the caller-supplied output. */
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|
           ((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void write16(uint8_t *p,uint16_t v) {
    p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);
}
static int32_t axis(int v,int bits) {
    int mid=bits==12?2048:128;
    int top=bits==12?4096:255;
    if (v<=mid) return -((int32_t)(mid-v)*32768+mid/2)/mid;
    return ((int32_t)(v-mid)*32767+(top-mid)/2)/(top-mid);
}
static int16_t flip_y(int32_t v) {
    if (v==32767)return -32768;
    if (v==-32768)return 32767;
    return (int16_t)-v;
}
static uint16_t flag(uint16_t mask,unsigned bit,int is_pressed) {
    return (uint16_t)(mask|(is_pressed?(uint16_t)(1u<<bit):0u));
}
static void output(uint8_t out[20],uint16_t buttons,uint8_t lt,uint8_t rt,
                   int32_t lx,int32_t ly,int32_t rx,int32_t ry,int invert_y) {
    int16_t v[4]={ (int16_t)lx, invert_y?flip_y(ly):(int16_t)ly,
                   (int16_t)rx, invert_y?flip_y(ry):(int16_t)ry };
    memset(out,0,20);out[1]=20;
    write16(out+2,buttons);
    out[4]=lt;out[5]=rt;
    for(int i=0;i<4;++i)write16(out+6+2*i,(uint16_t)v[i]);
}
int stadia_xusb_from_bruce_hid(const uint8_t *p,size_t n,uint8_t out[20],int invert_y) {
    if(!p||!out||n!=11||p[0]!=3||p[1]>8||invert_y<0||invert_y>1)
        return STADIA_CODEC_INVALID;
    uint16_t b=(uint16_t)p[2]|(uint16_t)((uint16_t)p[3]<<8);
    if (b&0x8000u)return STADIA_CODEC_RANGE;
    uint16_t m=0;
    m=flag(m,10,b&(1u<<4));m=flag(m,4,b&(1u<<5));m=flag(m,5,b&(1u<<6));
    m=flag(m,7,b&(1u<<7));m=flag(m,6,b&(1u<<8));
    m=flag(m,9,b&(1u<<9));m=flag(m,8,b&(1u<<10));
    m=flag(m,15,b&(1u<<11));m=flag(m,14,b&(1u<<12));
    m=flag(m,13,b&(1u<<13));m=flag(m,12,b&(1u<<14));
    switch (p[1]) {
    case 0:m|=1u;break;case 1:m|=1u|8u;break;
    case 2:m|=8u;break;case 3:m|=2u|8u;break;
    case 4:m|=2u;break;case 5:m|=2u|4u;break;
    case 6:m|=4u;break;case 7:m|=1u|4u;break;
    default:break;
    }
    output(out,m,p[8],p[9],axis(p[4],8),axis(p[5],8),
           axis(p[6],8),axis(p[7],8),invert_y);
    return STADIA_CODEC_OK;
}
int stadia_xusb_from_bruce_raw(const uint8_t *p,size_t n,uint8_t out[20],int invert_y) {
    if(!p||!out||n<0x34||n>4096||invert_y<0||invert_y>1)
        return STADIA_CODEC_INVALID;
    int32_t v[6];
    for(int i=0;i<6;++i){
        uint32_t value=read32(p+0x1c+4*i);
        if(value>4096)return STADIA_CODEC_RANGE;
        v[i]=(int32_t)value;
    }
    uint16_t m=0;
    m=flag(m,12,p[8]);m=flag(m,13,p[9]);m=flag(m,14,p[10]);m=flag(m,15,p[11]);
    m=flag(m,0,p[12]&&!p[13]);m=flag(m,1,p[13]&&!p[12]);
    m=flag(m,2,p[14]&&!p[15]);m=flag(m,3,p[15]&&!p[14]);
    m=flag(m,8,p[16]);m=flag(m,9,p[17]);
    m=flag(m,6,p[20]);m=flag(m,7,p[21]);
    m=flag(m,5,p[22]);m=flag(m,4,p[23]);m=flag(m,10,p[26]);
    uint8_t lt=(uint8_t)((v[4]*255+2048)/4096);
    uint8_t rt=(uint8_t)((v[5]*255+2048)/4096);
    output(out,m,lt,rt,axis(v[0],12),axis(v[1],12),
           axis(v[2],12),axis(v[3],12),invert_y);
    return STADIA_CODEC_OK;
}
int stadia_xusb_rumble_to_bruce(const uint8_t *p,size_t n,uint8_t out[5]) {
    if(!p||!out||n!=8||p[0]!=0||p[1]!=8||
       p[2]||p[5]||p[6]||p[7])return STADIA_CODEC_INVALID;
    uint16_t left=(uint16_t)((unsigned)p[3]*257u);
    uint16_t right=(uint16_t)((unsigned)p[4]*257u);
    out[0]=5;write16(out+1,left);write16(out+3,right);
    return STADIA_CODEC_OK;
}
