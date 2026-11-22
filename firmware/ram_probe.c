/* ARM-linked synthetic CPU diagnostic, NOT an installable Stadia firmware. */
#include "stadia_rt1061_inputs.h"
#include "stadia_xusb_codec.h"
#include <stdint.h>
__attribute__((used,section(".usb_dma"),aligned(64)))
volatile uint8_t stadia_usb_dma_staging[64];
__attribute__((used)) volatile uint32_t stadia_ram_probe_result;
__attribute__((used)) volatile uint8_t stadia_ram_probe_report[20];
void Reset_Handler(void) {
 const stadia_rt1061_calibration c={1734,578,1747,616};
 stadia_rt1061_sample s={0};
 uint8_t x[20];
 s.pressed_mask=1u<<4;
 s.hall_power_enabled=1; /* MOCK ONLY: no GPIO access */
 s.adc1[8]=1747;s.adc1[13]=1734;
 s.adc1[9]=2048;s.adc1[10]=2048;s.adc1[11]=2048;s.adc1[12]=2048;
 int status=stadia_rt1061_build_xusb(&s,&c,x,0);
 if(status==0)for(unsigned i=0;i<20;i++)stadia_ram_probe_report[i]=x[i];
 stadia_ram_probe_result=(status==0 && x[1]==20 && x[2]==0 && x[3]==0x10)
   ? 0x53584442u : 0xBADF00Du;
 for(;;){__asm volatile("wfi");}
}
