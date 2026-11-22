# Fase 104 — Transporte XUSB para MCU + integración futura con MCUXpresso

**Fecha:** 2026-11-22. **Alcance:** pruebas locales y compilación de *objetos relocatables* ARM Cortex-M7. **NO FLASH.** Ningún Stadia ni placa de desarrollo fue conectado o modificado.

## Trabajo nuevo probado

- `firmware_codec/stadia_xusb_transport.h/.c`: capa portable **C11**, envolviendo el conversor Bruce → XUSB de 20 bytes de fases 99–103.
- Estados USB: desconectado, configurado, transferencia IN pendiente/en curso, confirmación/error y reinicio de bus. **No envía paquetes**: el SDK real debe controlar USB y llamar estas funciones.
- Cola de profundidad 1 con último estado ganador; en un envío fallido, recupera el paquete salvo que haya una muestra más reciente. Evita colas de paquetes obsoletos.
- Procesa un paquete OUT de vibración de 8 bytes, devolviendo cinco bytes **lógicos** Bruce. No genera PWM ni mueve motores.
- Entrada HID Bruce (11 bytes) o mapa interno (12 bits); el significado GPIO/ADC requiere validación en hardware.
- Pruebas C nativas con UndefinedBehaviorSanitizer, pruebas Python `ctypes` y más de 7.800 pasos aleatorios simulando un host; compilación cruzada Clang como objetos **ELF32 ARM Cortex-M7 relocatables**. No se ejecuta código ARM.

## SDK NXP: el siguiente paso real

La [guía oficial MCUXpresso USB Device](https://mcuxpresso.nxp.com/mcuxsdk/latest/middleware/usb/docs/MCUXSDKUSBCOMDUG/topics/application_template.html) usa `USB_DeviceClassInit`, inicializa el reloj, `USB_DeviceEhciIsrFunction` y `USB_DeviceRun`. El SDK incluye controlador EHCI, clases USB y manejador de solicitudes estándar. **No proporciona una clase XUSB preparada** que podamos conectar sin trabajo adicional. Se necesitará implementar una clase Vendor/XUSB y verificar EP0/interrupt callbacks contra [el SDK NXP](https://github.com/nxp-mcuxpresso/mcuxsdk-middleware-usb).

**Contrato de integración esperado en una EVK‑MIMXRT1060 recuperable:**

1. Generar un proyecto de prueba nuevo del SDK NXP, habilitando EHCI USB Device. Utilizar una identidad USB **propia y legalmente asignada**. No reutilizar VID/PID comercial de Microsoft para un producto propio.
2. Crear la interfaz Vendor/XUSB con descriptores, EP0 y endpoints compatibles. La referencia Xbox 360 original presenta `FF/5D/01`, interrupt IN `0x81`, OUT `0x01`, `wMaxPacketSize=32`, reportes XUSB de 20 bytes. Es evidencia de laboratorio, no una identidad autorizada ni descriptor de producto listo para distribuir.
3. Desde `SET_CONFIGURATION(1)`, llamar a `stadia_xusb_transport_set_configured(&state,1)`; desde `BUS_RESET` o desconfiguración, cancelar las transferencias DMA y llamar `stadia_xusb_transport_bus_reset`.
4. Desde un ciclo de muestreo GPIO/ADC, llamar `queue_hid/raw`, `acquire_in` y **una sola** transferencia USB IN de 20 bytes por callback. Completar con `finish_in(state, success)` al recibir la notificación del SDK; indicar fracaso si el envío se rechaza. **El struct portable NO es un buffer DMA**: copiar a memoria alineada/no-cache según los requisitos del EHCI de NXP.
5. Desde callback de recepción USB OUT, validar la longitud 8 y pasar `process_out`; conectar la salida a una capa de motor separada con límites de corriente/voltaje. No escribir motor directamente desde USB.
6. Verificar en Windows con USBView y USBPcap la enumeración física; después confirmar enlazado del driver y reporte de botones en `joy.cpl`/`XInputGetState`. En Linux, contrastar `xpad`. Un nombre «Xbox» no significa que el sistema haya cargado XUSB.
7. Probar reconfiguración, suspensión/reanudación, errores de IN, desconexión durante DMA y resets. El adaptador debe **serializar callbacks**: este transporte no es thread-safe.

## Problema de identidad y driver Windows

El ejemplo público [espp XInput](https://esp-cpp.github.io/espp/buses/xinput_example.html) ha demostrado un controlador XUSB en ESP32-S3, con una variante composite que anuncia `XUSB10` a través de un descriptor **Microsoft OS 2.0**. Ese proyecto advierte expresamente que los VID/PID de Microsoft son solo para pruebas de emulación. **No sabemos si una identidad propia + `XUSB10` enlazará automáticamente XUSB en todas las versiones de Windows**: requiere medición en hardware real. No se deben inventar identificadores de fabricante para productos distribuidos.

## Resultados y bloqueos

| Comprobación | Estado |
|---|---|
| Conversor Xbox C11 en arquitectura M7 | **Sí**, objeto relocatable |
| Transporte XUSB C11 en arquitectura M7 | **Sí**, objeto relocatable |
| Reportes, reintentos y recepción rumble | **Sí**, simulación host |
| Proyecto MCUXpresso enlazado con SDK oficial | **No** |
| Firmware ejecutable en EVK‑MIMXRT1060 | **No** |
| Windows detecta nuestra placa como XInput | **No** |
| Stadia real ejecuta firmware propio | **No; HAB CLOSED no resuelto** |
| Autenticación en consola Xbox | **No** |

**NO FLASH:** No usar bootloader CDC, RAM flashloader, ROM SDP, `FIELD_RETURN`, eFuses ni modificaciones SPI. El siguiente avance requiere hardware de desarrollo independiente, no experimentar con la unidad Stadia comercial.


## Resultado de GitHub Actions

[Workflow dedicado de fase 104](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45074690362): **14/14 pruebas superadas** tanto en Python 3.11 como en Python 3.12. Incluye compilación nativa C con UBSan, pruebas `ctypes`, simulación de eventos de host y compilación cruzada ARM Cortex-M7 con Clang. Estos 14 tests son **nuevos**; no se declara reevaluada la suite completa de fases previas en este commit. Esta ejecución no usa hardware.

