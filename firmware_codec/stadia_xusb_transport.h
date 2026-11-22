#ifndef STADIA_XUSB_TRANSPORT_H
#define STADIA_XUSB_TRANSPORT_H
/* Firmware-independent XUSB report transfer state machine. No USB driver. */
#include <stddef.h>
#include <stdint.h>
#include "stadia_xusb_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  STADIA_XUSB_OUT_REPORT_SIZE = 8,
  STADIA_XUSB_QUEUE_DEPTH = 1
};

typedef enum {
  STADIA_TRANSPORT_OK = 0,
  STADIA_TRANSPORT_NOT_CONFIGURED = -1,
  STADIA_TRANSPORT_INVALID = -2,
  STADIA_TRANSPORT_BUSY = -3
} stadia_transport_status;

typedef struct {
  uint8_t configured;
  uint8_t in_flight;
  uint8_t pending;
  uint8_t tx[STADIA_XUSB_REPORT_SIZE];
  uint8_t last_sent[STADIA_XUSB_REPORT_SIZE];
  uint32_t tx_completions;
  uint32_t tx_errors;
  uint32_t pending_replacements;
  uint32_t rx_valid;
  uint32_t rx_invalid;
} stadia_xusb_transport;

/* Caller must serialize callbacks. This is deliberately NOT thread safe. */
void stadia_xusb_transport_init(stadia_xusb_transport *s);
void stadia_xusb_transport_bus_reset(stadia_xusb_transport *s);
void stadia_xusb_transport_set_configured(stadia_xusb_transport *s, int configured);

/* Queue latest report only; no implicit USB transmission or DMA access. */
int stadia_xusb_transport_queue_hid(stadia_xusb_transport *s,
                                    const uint8_t *src, size_t length, int invert_y);
int stadia_xusb_transport_queue_raw(stadia_xusb_transport *s,
                                    const uint8_t *src, size_t length, int invert_y);

/* Returns BUSY when another IN is in flight or nothing is pending.
 * Returned packet must be submitted to a USB IN endpoint by the application.
 * If the USB submit itself fails, call finish_in(..., 0) to permit retry. */
int stadia_xusb_transport_acquire_in(stadia_xusb_transport *s,
                                     uint8_t out[STADIA_XUSB_REPORT_SIZE]);
int stadia_xusb_transport_finish_in(stadia_xusb_transport *s, int success);

/* Decode a controller-side USB OUT packet, returning a 5-byte logical Bruce
 * rumble payload. The application must decide whether/how to drive a motor. */
int stadia_xusb_transport_process_out(stadia_xusb_transport *s,
                                      const uint8_t *data, size_t length,
                                      uint8_t rumble[STADIA_BRUCE_RUMBLE_SIZE]);

#ifdef __cplusplus
}
#endif
#endif
