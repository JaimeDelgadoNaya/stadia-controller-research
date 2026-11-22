#include "stadia_xusb_transport.h"
#include <string.h>

void stadia_xusb_transport_init(stadia_xusb_transport *s) {
  if (s != NULL) memset(s, 0, sizeof(*s));
}

void stadia_xusb_transport_bus_reset(stadia_xusb_transport *s) {
  if (!s) return;
  s->configured = 0;
  s->in_flight = 0;
  s->pending = 0;
  memset(s->tx, 0, sizeof(s->tx));
  memset(s->last_sent, 0, sizeof(s->last_sent));
}

void stadia_xusb_transport_set_configured(stadia_xusb_transport *s, int configured) {
  if (!s) return;
  if (!configured) {
    stadia_xusb_transport_bus_reset(s);
  } else if (!s->configured) {
    s->in_flight = 0;
    s->pending = 0;
    s->configured = 1;
  }
}

static int store(stadia_xusb_transport *s, const uint8_t *report) {
  if (!s || !report) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  if (s->pending) s->pending_replacements++;
  memcpy(s->tx, report, sizeof(s->tx));
  s->pending = 1;
  return STADIA_TRANSPORT_OK;
}

int stadia_xusb_transport_queue_hid(stadia_xusb_transport *s,
                                   const uint8_t *src, size_t length, int invert_y) {
  uint8_t report[STADIA_XUSB_REPORT_SIZE];
  if (!s || !src) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  if (stadia_xusb_from_bruce_hid(src,length,report,invert_y) != STADIA_CODEC_OK)
    return STADIA_TRANSPORT_INVALID;
  return store(s,report);
}

int stadia_xusb_transport_queue_raw(stadia_xusb_transport *s,
                                   const uint8_t *src, size_t length, int invert_y) {
  uint8_t report[STADIA_XUSB_REPORT_SIZE];
  if (!s || !src) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  if (stadia_xusb_from_bruce_raw(src,length,report,invert_y) != STADIA_CODEC_OK)
    return STADIA_TRANSPORT_INVALID;
  return store(s,report);
}

int stadia_xusb_transport_acquire_in(stadia_xusb_transport *s, uint8_t out[STADIA_XUSB_REPORT_SIZE]) {
  if (!s || !out) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  if (!s->pending || s->in_flight) return STADIA_TRANSPORT_BUSY;
  memcpy(out, s->tx, sizeof(s->tx));
  memcpy(s->last_sent, s->tx, sizeof(s->tx));
  s->pending = 0;
  s->in_flight = 1;
  return STADIA_TRANSPORT_OK;
}

int stadia_xusb_transport_finish_in(stadia_xusb_transport *s, int success) {
  if (!s) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  if (!s->in_flight) return STADIA_TRANSPORT_BUSY;
  s->in_flight = 0;
  if (success) {
    s->tx_completions++;
  } else {
    s->tx_errors++;
    /* Only restore the failed packet if no newer sample has arrived. */
    if (!s->pending) {
      memcpy(s->tx, s->last_sent, sizeof(s->tx));
      s->pending = 1;
    }
  }
  return STADIA_TRANSPORT_OK;
}

int stadia_xusb_transport_process_out(stadia_xusb_transport *s,
                                     const uint8_t *data, size_t length,
                                     uint8_t rumble[STADIA_BRUCE_RUMBLE_SIZE]) {
  if (!s || !rumble || !data) return STADIA_TRANSPORT_INVALID;
  if (!s->configured) return STADIA_TRANSPORT_NOT_CONFIGURED;
  uint8_t local[STADIA_BRUCE_RUMBLE_SIZE];
  if (stadia_xusb_rumble_to_bruce(data,length,local) != STADIA_CODEC_OK) {
    s->rx_invalid++;
    return STADIA_TRANSPORT_INVALID;
  }
  memcpy(rumble,local,sizeof(local));
  s->rx_valid++;
  return STADIA_TRANSPORT_OK;
}
