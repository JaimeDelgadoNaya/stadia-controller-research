# Fases 107 y 108: ruta de ejecución temporal RAM y código ARM hacia XUSB

**22/11/2026. Estado: avance offline, sin ejecución física ni firmware instalable.**

## Evidencia independiente consultada

- [gomezluisj/stadia-controller-re](https://github.com/gomezluisj/stadia-controller-re) documenta sobre una placa Stadia H2B PVT ejecución temporal por ROMC, consola USB CDC desde OCRAM, 17 botones y seis entradas ADC. Es una **afirmación de un tercero**, no un experimento reproducido por nosotros.
- [bare-metal bringup](https://github.com/gomezluisj/stadia-controller-re/blob/67e58b14b1b863ca7654408a2676baf3dbdc59e5/docs/bare-metal-bringup.md), blob Git 4d9c9c2a22a791df0c11428a4f4a8f468450ca6d; [hardware pinout](https://github.com/gomezluisj/stadia-controller-re/blob/67e58b14b1b863ca7654408a2676baf3dbdc59e5/docs/hardware-pinout.md), blob 1f0450b36cf3c549ba19e182a108e021e25095ec. Esos documentos detallan la restricción USB1 DMA -> OCRAM (no DTCM), la alimentación activa en bajo de gatillos Hall por GPIO2_10 y mapas ADC1 IN8..13.
- [tchebb/nxp-sdp-overrun](https://codeberg.org/tchebb/nxp-sdp-overrun): el repositorio original **no pudo descargarse** desde el entorno de análisis; no se ha auditado fuente, reproducido exploit ni certificado el desbloqueo de esta unidad.
- [NXP MCUXpresso USB device HID generic lite para MIMXRT1060-EVKB](https://docs.mcuxpresso.nxp.com/mcuxsdk/25.06.00/html/examples/usb_examples/usb_device_hid_generic_lite/readme.html): referencia para futura integración USB, no es una implementación XUSB ni garantiza driver XInput.

## Trabajo implementado

1. firmware/stadia_rt1061_inputs.h y .c: convierte 17 GPIO lógicos (normalizados desde activo bajo) y seis muestras ADC1 IN8..13 a la representación interna del codec XUSB. No lee ni escribe ningún registro. Assistant y Capture no se asignan a un botón Xbox; direcciones opuestas se neutralizan mediante el codec.
2. Interbloqueo Hall: se rechazan muestras cuando la HAL no confirma que ha alimentado los gatillos. Valores **de laboratorio, no universales**: L2 canal 13 reposo 1734, pulsado 578; R2 canal 8 reposo 1747, pulsado 616. Hay que calibrarlos individualmente y comprobar ruido, batería y carga.
3. firmware/startup_ram_probe.S, firmware/ram_probe.ld, firmware/ram_probe.c y firmware/memset_freestanding.c: **un ELF32 ARM Cortex-M7 enlazado** para una ventana OCRAM supuesta de 128 KiB desde 0x20200000, con tabla de vectores, marcador de autocomprobación y sección usb_dma de 64 B, alineada en OCRAM. La configuración real FlexRAM debe medirse antes de probarlo en un chip.
4. El ELF solo calcula en CPU un reporte XUSB sintético con botón A. No ejecuta USB real, no inicializa GPIO/ADC/relojes, no accede a flash ni OTP, no es IVT firmada y no se ha ejecutado físicamente. El carácter ELF EXEC no autoriza el arranque bajo HAB CLOSED.
5. tools/build_ram_probe.py y tests/test_phase108.py generan e inspeccionan el ELF; tests/test_rt1061_inputs.c cubre los 17 botones, SOCD, rangos de gatillos, falta de excitación, valores anómalos, serialización XUSB y transporte con sanitizador UBSan.

## Reproducir

Se necesitan Python 3, clang con target arm-none-eabi, ld.lld, readelf y cc. Ejecución puramente offline:

```sh
python tools/build_ram_probe.py
python -m unittest discover -s tests -p 'test_phase108.py' -v
```

**Resultado local:** 8 pruebas Python correctas, test C con UBSan correcto, ELF ARM enlazado con entrada Thumb en OCRAM y sección usb_dma de 64 B alineada. Este resultado no incluye reconocimiento Windows ni firmware USB real.

## Siguiente hito y NO-GO

- Preparar USB XUSB en una placa MIMXRT1060-EVKB recuperable usando el SDK oficial; capturar descriptor, IN/OUT y asociación real del driver Windows. HID genérico no basta para XInput.
- Conseguir el código auténtico nxp-sdp-overrun y auditar compatibilidad y efectos en una unidad de pruebas antes de realizar cualquier ejecución temporal.
- **NO FLASH** el bootloader USB CDC, **NO FIELD_RETURN**, no modificar la flash ni fusibles del mando del usuario; sin una ruta de recuperación demostrada no hay instalación permanente segura.
