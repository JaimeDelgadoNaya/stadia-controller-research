#include "../firmware_codec/stadia_xusb_transport.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t neutral[11]={3,8,0,0,128,128,128,128,0,0,0};
static uint8_t abc[11]={3,8,0,0,128,128,128,128,0,0,0};
static uint8_t changed[11]={3,0,0,0,255,0,128,128,200,1,0};

int main(void){
  stadia_xusb_transport s;
  uint8_t p[20],r[5]={9,9,9,9,9};
  const uint8_t out_good[8]={0,8,0,255,100,0,0,0};
  const uint8_t out_bad[8]={0,8,0,255,100,0,1,0};
  stadia_xusb_transport_init(&s);
  assert(stadia_xusb_transport_queue_hid(&s,neutral,sizeof(neutral),0)==STADIA_TRANSPORT_NOT_CONFIGURED);
  stadia_xusb_transport_set_configured(&s,1);
  assert(stadia_xusb_transport_queue_hid(&s,neutral,sizeof(neutral),0)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_acquire_in(&s,p)==STADIA_TRANSPORT_OK);
  assert(p[0]==0 && p[1]==20);
  assert(stadia_xusb_transport_acquire_in(&s,p)==STADIA_TRANSPORT_BUSY);
  abc[2]=0x10; /* guide pressed */
  assert(stadia_xusb_transport_queue_hid(&s,abc,sizeof(abc),0)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_queue_hid(&s,changed,sizeof(changed),0)==STADIA_TRANSPORT_OK);
  assert(s.pending_replacements==1);
  assert(stadia_xusb_transport_finish_in(&s,0)==STADIA_TRANSPORT_OK);
  assert(s.tx_errors==1 && s.pending==1);
  assert(stadia_xusb_transport_acquire_in(&s,p)==STADIA_TRANSPORT_OK);
  assert(p[4]==200 && p[5]==1);
  assert(stadia_xusb_transport_finish_in(&s,1)==STADIA_TRANSPORT_OK);
  assert(s.tx_completions==1);
  assert(stadia_xusb_transport_queue_hid(&s,neutral,sizeof(neutral),0)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_acquire_in(&s,p)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_finish_in(&s,0)==STADIA_TRANSPORT_OK);
  assert(s.pending==1); /* failed IN is retried if no newer sample */
  assert(stadia_xusb_transport_acquire_in(&s,p)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_finish_in(&s,1)==STADIA_TRANSPORT_OK);
  assert(stadia_xusb_transport_process_out(&s,out_good,8,r)==STADIA_TRANSPORT_OK);
  assert(r[0]==5 && r[1]==255 && r[2]==255);
  assert(stadia_xusb_transport_process_out(&s,out_bad,8,r)==STADIA_TRANSPORT_INVALID);
  assert(s.rx_valid==1 && s.rx_invalid==1);
  assert(stadia_xusb_transport_queue_hid(&s,neutral,10,0)==STADIA_TRANSPORT_INVALID);
  stadia_xusb_transport_bus_reset(&s);
  assert(s.pending==0 && s.in_flight==0 && s.configured==0);
  assert(stadia_xusb_transport_process_out(&s,out_good,8,r)==STADIA_TRANSPORT_NOT_CONFIGURED);
  puts("USB transport tests passed (no device IO)");
  return 0;
}
