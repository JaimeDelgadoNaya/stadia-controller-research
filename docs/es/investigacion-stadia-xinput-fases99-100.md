# Fases 99–100 — Stadia como mando Xbox 360/XInput (investigación offline)

**22/11/2026.** Se estudió la **modificación del firmware original del mando Stadia**, no el uso de ViGEm en PC. Ninguna acción sobre dispositivos y ningún flasheo realizado. El código en esta rama es **prototipo y herramientas de validación, no firmware arrancable**.

## 1. Avances concretos

- `tools/simulate_xinput_phase99.py`: convierte la trama HID Bruce de **11 bytes** (hat, 15 botones, cuatro ejes u8, LT/RT u8, Consumer) a la trama **Xbox 360/XUSB de 20 bytes**. Botones A/B/X/Y, D-pad, LB/RB, Start/Back, stick clicks y Guide. Assistant/Capture quedan explícitamente sin homólogo.
- También acepta una **representación sintética** del productor interno de Bruce: buttons `+0x08…+0x1a`, cuatro ejes `uint32` a `+0x1c/+0x20/+0x24/+0x28` y gatillos `+0x2c/+0x30` en el rango `0…0x1000` (centro `0x800`). **Los 12 bits vienen de la nota de análisis de terceros y no de RAM leída por nosotros**.
- Convierte la vibración de salida Xbox (8 bytes, u8/u8) a reporte HID Stadia **ID 5** con amplitudes de 16 bits. Esto únicamente crea bytes; no activa motores.
- `firmware_codec/stadia_xusb_codec.c/.h`: conversor **C11 independiente del hardware**, sin enlace a SDK NXP, controlador USB, firma de firmware ni motor de arranque.
- `tests/test_xinput_codec_c_phase100.py`: compila C11 con `cc` en un directorio temporal y compara **500 reportes HID sintéticos y 1.000 variantes raw de 12 bits** contra la implementación Python. Comprueba el rumble y los datos inválidos. Este archivo no comunica con ningún dispositivo.
- `tools/audit_xusb_usb_phase100.py`: reconstruye los **18 bytes del descriptor dispositivo** y **153 bytes de la configuración** de un Xbox 360 original cableado, con cuatro interfaces USB de clase vendor (incluida XSM3). **No es un descriptor HID genérico**; XUSB transmite reportes de 20 bytes.
- `tools/audit_boot_readiness_phase100.py`: parser de la IVT NXP y comprobación de riesgos HAB sin writes ni ROM downloader. La **presencia de CSF no demuestra que la firma sea válida** y la entrada SDP **no omite** la autenticación del arranque.

## 2. Evidencia de los archivos aportados

| Muestra del usuario | Observación de análisis estático | Conclusión |
|---|---|---|
| `bluetooth-image-public.md` (Bruce 337784) | Reporte HID y productor raw de 12 bits; motor vibración de dos amplitudes | Sirve de especificación de codec, no de interfaz de firmware documentada por Google |
| `message.txt` | El autor refiere comando Class USB 0xC0 sobre aplicación Gotham build 169429 | No extrapolar a bootloader ni a Bruce; un ACK no significa SDP |
| `bootloader-usb-acm(1).bin` | 94.248 bytes, **72 bytes distintos** en el prefijo del bootloader A original de 131.072, sin puntero CSF y truncado | **No** permite afirmar que HAB CLOSED lo ejecute |
| `thebb_ivt_flashloader.bin` | 98.148 bytes, IVT a +0x400, sin CSF y Boot Data declara 98.304 bytes, **156 más** | No está demostrado como imagen recuperable o ejecutable en retail |
| `led-public.md` | LP5562 con canales rojo/ámbar/blanco según la placa descrita | Sin equivalencia directa al anillo de 4 jugadores Xbox |
| `bluetooth(1).bin` | Almacén privado de emparejamiento | **Excluido** del código, evidencia y repositorio |
| `fwlog-kit.zip` | Herramientas de diagnóstico/SDP/parches del autor | **No se ejecutaron**; placa dev ≠ mando comercial |

El firmware de Xbox 360 **no puede obtenerse** simplemente renombrando un HID o cambiando VID/PID. El ejemplo de referencia es dispositivo vendor-specific `045e:028e`, interfaz gamepad `FF/5D/01`, IN `0x81`, OUT `0x01`. Se trata de los IDs de Microsoft **solo para investigación**, no autorizan su uso en productos distribuidos.

## 3. Objetivos, por viabilidad

| Objetivo | Conclusión ahora |
|---|---|
| Conversión de datos Stadia → XUSB 20 bytes | **Implementado y verificado offline** |
| Codec portable C11 reutilizable | **Implementado**, no enlazado al SDK del RT1061 |
| Perfil USB Xbox 360 original | **Analizado y validado estructuralmente** sin enumeración real |
| Windows PC reconociendo el Stadia físicamente como Xbox 360 | **No demostrado** |
| Firmware custom ejecutándose en Stadia retail HAB CLOSED | **No demostrado: principal bloqueo** |
| Xbox 360/One/Series física | **No demostrado**; autenticación de consola es un problema adicional |
| Switch 2 | Investigación NS1 Pro anterior en fases 96–98; protocolo distinto de XUSB |

XInput para PC no requiere autenticación de consola en las implementaciones conocidas (GP2040-CE). Las consolas sí tienen un mecanismo de autorización; que Windows acepte la emulación no validará su aceptación en Xbox.

## 4. Qué debemos hacer antes de usar hardware

1. **P0: viabilidad de arranque seguro/recuperación.** Validar exacta revisión de placa, estado HAB, firma autorizada y procedimiento de recuperación **sin escribir**. SDP no equivale a firma valida. Mantener prohibido `FIELD_RETURN`/eFuses.
2. **P1: implementar un controlador USB XUSB real en placa de desarrollo recuperable** (por separado, RT1061 compatible) y probar enumeración en Windows contra una captura de un Xbox 360 real; fuente externa solo demuestra un ejemplo con ESP32-S3, no el Stadia.
3. **P2: integrar el codec C con el productor de 12 bits y rumble Stadia** bajo firmware firmable/recuperable, solo cuando P0 esté demostrado.
4. **P3: Xbox física opcional**, evaluando mecanismos de autenticación legítimos de manera independiente. No confundir con PC.

## 5. Pruebas y límites

Paquete autónomo descargable desde la conversación: **57 pruebas Python, 1.500 vectores C ↔ Python**, pasadas localmente con compilador C11. La batería del repositorio integra pruebas adicionales sobre esa misma arquitectura y se valida con GitHub Actions, sin acceso físico a dispositivos.

Pruebas sintéticas de software **no equivalen a prueba de firmware real ni a reconocimiento de mando por Windows**. No se ejecutó ningún exploit, lectura de claves, parches de flash, USB Vendor, SDP, writes KVS ni eFuse.

## 6. Fuentes

- Datos aportados en esta investigación: `bluetooth-image-public.md`, `message.txt`, `fwlog-kit.zip`, `led-public.md` y los binarios.
- [Captura USB genuina Xbox 360 (David Madison)](https://www.partsnotincluded.com/understanding-the-xbox-360-wired-controllers-usb-data/)
- [GP2040-CE: XInput en PC sin autenticación](https://gp2040-ce.info/web-configurator/menu-pages/settings/)
- [espp: dispositivo XUSB de demostración para ESP32-S3](https://esp-cpp.github.io/espp/buses/xinput_example.html)
- [NXP: imágenes firmadas de RT1060/1061](https://docs.mcuxpresso.nxp.com/mcuxsdk/latest/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/program_bootable_image.html)
- [HAB OPEN vs CLOSED: nota técnica NXP](https://community.nxp.com/t5/Other-NXP-Products/i-MXRT106x-HAB-closed-boot-fail-HAB-log-stops-at-AUTHENTICATION/m-p/2410743)
