#ifndef STADIA_XUSB_CODEC_H
#define STADIA_XUSB_CODEC_H
/* Pure C11 codec: NO USB, flash, bootloader, keys or device I/O. */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { STADIA_XUSB_REPORT_SIZE=20, STADIA_BRUCE_HID_REPORT_SIZE=11,
       STADIA_BRUCE_INTERNAL_MIN_SIZE=0x34, STADIA_BRUCE_RUMBLE_SIZE=5 };
typedef enum {
    STADIA_CODEC_OK=0, STADIA_CODEC_INVALID=-1, STADIA_CODEC_RANGE=-2
} stadia_codec_status;
/* invert_y is a testable orientation hypothesis based on Bruce notes. */
int stadia_xusb_from_bruce_hid(const uint8_t *src,size_t n,uint8_t out[20],int invert_y);
int stadia_xusb_from_bruce_raw(const uint8_t *src,size_t n,uint8_t out[20],int invert_y);
int stadia_xusb_rumble_to_bruce(const uint8_t *src,size_t n,uint8_t out[5]);
#ifdef __cplusplus
}
#endif
#endif
