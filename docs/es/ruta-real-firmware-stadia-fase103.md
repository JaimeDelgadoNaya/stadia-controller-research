# Fase 103 — Ruta real hacia firmware Xbox nativo en Google Stadia

**Fecha:** 22-11-2026 · **Estado:** compilación cruzada ARM validada, auditoría de firmas estática, instalación retail **NO-GO**. 

## Decisión técnica

La conversión Stadia→Xbox/XUSB en Python y C11 ya estaba comprobada offline en las fases 99–102; la instalación A/B de las fases 101–102 era **solo un simulador lógico con firmas inventadas**. El bloqueo decisivo en un Stadia real es la cadena de arranque, no el formato de 20 bytes del reporte Xbox.

Se avanza en dos frentes paralelos, sin confundirlos:
1. **Hardware de desarrollo recuperable:** compilar el codec para Cortex-M7 y preparar su futura integración con USB y entradas del mando; no alterar firmware Google.
2. **Mando comercial:** delimitar exactamente qué verificaciones de firma y estado HAB siguen sin demostrarse; no ejecutar SDP, escritura ni `FIELD_RETURN`.

## Avance nuevo y reproducible: código ARM Thumb-2

- El **mismo** `firmware_codec/stadia_xusb_codec.c` de las fases anteriores se ha compilado con Clang 17, target `armv7em-none-eabi`, CPU `cortex-m7`, Thumb, float ABI soft, flags `-ffreestanding -fno-builtin -O2 -Wall -Wextra -Werror -std=c11`.
- Archivo de salida **objeto relocatable ELF32 ARM EABI5** de **2.540 bytes**. SHA-256 del objeto reproducido en este entorno: `26deeeef21d46024a9cb2ad0574356ade82bbcd51b39d3364855c527fadfa6d6`. Otro compilador o versión podría generar bytes diferentes.
- Símbolos exportados: `stadia_xusb_from_bruce_hid`, `stadia_xusb_from_bruce_raw`, `stadia_xusb_rumble_to_bruce`.
- Dependencia de runtime sin resolver: `memset`. Se incluye una **cabecera mínima de declaración** para compilación freestanding, **no una libc/USB ni imagen arrancable**.
- La herramienta `tools/verify_arm_codec_phase103.py` valida con parser ELF la máquina ARM, EABI5, tipo *relocatable*, tabla de símbolos y tres funciones. **Rechaza un ELF ejecutable** para evitar presentar un objeto como firmware instalable. Tests offline y objetivo Clang reproducibles.

```bash
python -m tools.verify_arm_codec_phase103 --codec-dir firmware_codec --out-dir ./build/arm_phase103
python -m unittest tests.test_arm_boot_evidence_phase103 -v
```

**Resultado local:** 13/13 pruebas. Sin USB real, sin boot, sin contacto con el mando. Este código es la base de un posible puerto a RT1061 con USB device stack y control de GPIO, cuando exista un entorno de ejecución autorizado.

## Auditoría de cuatro imágenes originales suministradas (solo lectura)

La documentación oficial de NXP define IVT con el puntero CSF en `IVT+0x18`, y diferencia presencia del CSF de la verificación criptográfica HAB. [NXP: i.MX RT bootable image](https://mcuxpresso.nxp.com/mcuxsdk/25.06.00/html/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/imx_rt_bootable_image.html).

| Muestra | Tamaño archivo | IVT offset | CSF pointer | ¿Bytes CSF dentro de ESTE archivo? | Consecuencia |
|---|---:|---:|---|---|---|
| Bootloader A original | 131.072 | `0x0` | `0x60818000` | **No**; equivale a offset `0x817000` respecto a base inferida `0x60001000` | Con el fichero de solo 128 KB **no se dispone del bloque firmado completo para comprobarlo**. |
| Bootloader CDC modificado | 94.248 | `0x0` | **0** | No | Descriptor USB parcheado, **no** firma apta para retail. |
| Flashloader RAM aportado | 98.148 | `0x400` | **0** | No | Tampoco valida ejecución bajo HAB CLOSED. |
| Bruce original, imagen firmada | 1.050.984 | `0xFF000` | `0x6013F030` | **Sí**, comienzo `D4 00 48 42` en `0xFF030` | Solo verificación estructural CSF; **no** autenticación criptográfica ni lectura de claves eFuse. |

Esta precisión es relevante: hablar de «bootloader firmado» porque en la cabecera aparece `0x60818000` no permite verificar su firma **si el bloque CSF señalado no está dentro de los 128 KB del archivo**. No se debe inferir que el bootloader completo sea inválido: la referencia puede apuntar a otra región de la flash que **no está incluida** en esa copia.

El informe de ingeniería inversa de Bruce suministrado por el usuario afirma que el bootloader comprueba las estructuras de aplicación y el flujo de slots, pero estas notas **no permiten concluir que el estado HAB de un ejemplar retail concreto sea OPEN o CLOSED**. En terceros se ha comunicado HAB cerrado y comprobaciones RSA de Google; faltan registros reproducibles sobre esta unidad.

## ¿Por qué no usar directamente el cargador USB CDC aportado?

El autor advierte expresamente del riesgo de dejar el mando inutilizado, en particular en una unidad bloqueada. Nuestra comparación estática documentó **72 bytes cambiados**, pérdida del puntero CSF y truncamiento. No es un desbloqueo HAB, ni una imagen Xbox, ni una recuperación demostrada. **NO FLASH**.

Entrar en ROM SDP mediante el dispatcher de la aplicación Gotham (reportado para build 169429) no autentica ni autoriza una imagen nueva. El modelo de BootROM ROM SDP y la firma HAB deben verificarse por separado. La vía `FIELD_RETURN`/eFuses **no es una herramienta de desbloqueo rutinaria**.

## Alternativas que realmente funcionan antes de reflashear el mando

- **Firmware Xbox para otro MCU, reversible:** [jfedor2/portable-gamepad-firmware](https://github.com/jfedor2/portable-gamepad-firmware) tiene modo PC que se presenta como Xbox 360 por cable y modo Nintendo Switch por cable, pero funciona en **sus placas compatibles**. No se puede instalar directamente en Stadia sin portar y sin superar su arranque seguro.
- **Mando Stadia sin tocar + adaptador ESP32-S3:** [danzig666/stadia-dongle-esp](https://github.com/danzig666/stadia-dongle-esp) declara que convierte Stadia BLE en USB Xbox 360 en Windows, usando ESP32-S3 con USB nativo. Es la ruta pública más corta hacia usar el Stadia realmente como Xbox sin tocar sus firmas; **sí requiere un adaptador externo**, no cumple el objetivo de firmware dentro del mando. No ha sido probado físicamente por nosotros.
- **Wi-Fi Stadia sin flashear:** [jkfran/stadiacast](https://github.com/jkfran/stadiacast) permite utilizar el modo Wi-Fi existente y virtualizar un mando en PC (según su documentación actual); no es firmware nativo.

## Orden de hitos y condiciones de aceptación

| Paso | Prueba que falta | Regla de paso |
|---|---|---|
| A. Codec Cortex-M7 | **OBJETO ARM** compilado y validado offline | **Cumplido** en fase 103 |
| B. USB XUSB en placa recuperable | Captura de descriptores, endpoints, polling y binding real de Windows | No confundir formato XUSB con enumeración/binding |
| C. Lectura de inputs de placa | GPIO, ADC, USB y rumble reales con pruebas manuales seguras | No asumir que nuestros offsets Bruce son APIs del hardware |
| D. Seguridad de una unidad Stadia | Estado HAB y cadena de confianza **verificados por método de solo lectura** y revisión identificada | No asumir HAB OPEN; si CLOSED, sin firma autorizada = NO-GO |
| E. Recuperación retail | Protocolo probado en hardware de repuesto/placa recuperable, imagen autenticada y respaldo | Sin evidencia no realizar escritura |
| F. Firmware nativo Stadia | USB Xbox XUSB funcionando en mando comercial y boot validado | **Objetivo final aún sin demostrar** |

## Límites que no deben ocultarse

**No existe un `.bin` instalable para Stadia**, ni una firma de Google ni una cadena HAB autorizada validada. La compilación ARM demuestra **compatibilidad de la parte de cálculo con Cortex-M7**, nada sobre ejecución real, periféricos o firmas. Las 13 pruebas nuevas son estáticas / compilación, no ensayos de Windows o del mando.

No se han ejecutado comandos de hardware, SDP, parches de flash, scripts de explotación, cambios de bootloader, lectura de `#BONDING` ni escritura de eFuses.
