#ifndef STADIA_RT1061_INPUTS_H
#define STADIA_RT1061_INPUTS_H
/* GPIO/ADC snapshots only: no registers/flash/boot/USB. */
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
 STADIA_RT1061_BUTTON_COUNT=17, STADIA_RT1061_RAW_LENGTH=0x34,
 STADIA_RT1061_ADC_CHANNELS=14, STADIA_RT1061_OK=0,
 STADIA_RT1061_BAD_INPUT=-1, STADIA_RT1061_HALL_NOT_POWERED=-2,
 STADIA_RT1061_BAD_CALIBRATION=-3
};
typedef struct {
 uint32_t pressed_mask; /* logical pressed bits from active-LOW GPIO idx 0..16 */
 uint16_t adc1[STADIA_RT1061_ADC_CHANNELS]; /* channels 8..13 sampled */
 uint8_t hall_power_enabled; /* HAL ensures GPIO2_10 drives LOW before asserting */
} stadia_rt1061_sample;
typedef struct {
 uint16_t left_rest, left_full, right_rest, right_full;
} stadia_rt1061_calibration;
int stadia_rt1061_build_raw(const stadia_rt1061_sample *sample,
                           const stadia_rt1061_calibration *cal,
                           uint8_t raw[STADIA_RT1061_RAW_LENGTH]);
int stadia_rt1061_build_xusb(const stadia_rt1061_sample *sample,
                            const stadia_rt1061_calibration *cal,
                            uint8_t out[20], int invert_y);
#ifdef __cplusplus
}
#endif
#endif
