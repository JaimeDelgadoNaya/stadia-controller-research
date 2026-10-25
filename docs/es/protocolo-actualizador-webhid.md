# Paquete A — Protocolo real del actualizador archivado

**Estado: completado, exclusivamente mediante inspección de código.** No se ha iniciado el actualizador en el navegador, no se ha conectado el mando, ni se ha enviado ningún paquete USB o HID. Esta investigación reemplaza la búsqueda indefinida de punteros del bootloader A.

## Fuente y garantía de reproducción

Se inspeccionó el JavaScript original conservado en
[hazrpg/stadia-flasher — controller/app_combined.js](https://github.com/hazrpg/stadia-flasher/blob/main/controller/app_combined.js):
**149.810 bytes**, SHA-1 del objeto Git `3c877738c12e7d5750714cd0770935ad39bd9990`.
Es un archivo JavaScript compilado con Closure y nombres de función minimizados. Los nombres `bj`, `fj`, etc. son **identificadores de ese archivo exacto**, no API públicas ni símbolos del firmware.

Como contraste independiente se consultaron [stadiatool/sdp.py](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/sdp.py)
y [stadiatool/flashloader.py](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/flashloader.py).
Sus identificadores de comando y formato HID concuerdan con la herramienta archivada. Ese contraste **no** significa que hayamos desensamblado todos los manejadores internos de ROM y flashloader.

## Hallazgo decisivo

**El actualizador de Google no envía la imagen al Bulk OUT 0x07 del bootloader A.**
En esta versión de JavaScript hay **cero llamadas `transferOut`/`transferIn` de WebUSB**.
La instalación se organiza alrededor de **WebHID**:

| Modo | VID:PID | Transporte/uso observado |
|---|---|---|
| Normal | `18D1:9400` | WebUSB: versión y batería, consultas de estado |
| Bootloader | `18D1:946B` | Enumeración y selección de modo, no ruta de datos de programación en este script |
| ROM SDP NXP | `1FC9:0135` | WebHID: carga del cargador firmado en RAM y salto |
| Cargador firmado RAM | `15A2:0073` | WebHID: identificar flash, configurar, borrar, escribir y reiniciar |

Los cuatro identificadores están en `mm`; la selección de modo se hace en la lógica de UI. Que uno de ellos figure entre los filtros **no significa que el navegador le envíe un comando de flasheo**.

## Matriz host → receptor → validaciones

| Paso | Función JS | Orden o petición que realmente construye | Receptor / validación |
|---|---|---|---|
| 1. Identificación | `Aj` / `Bj` / `Dj` | WebUSB interfaz clase, **IN 0x81**, 64 bytes | Aplicación normal; lee versión little-endian, **no** escribe firmware |
| 2. Batería | `Cj` / `Ej` | WebUSB clase **OUT 0x83**, pausa de 500 ms, **IN 0x84** | Aplicación normal; la interfaz UI exige batería conocida `≥10 %` |
| 3. Arranque de cargador firmado | `wm` / `bj` / `cj` | HID report 1, SDP **WRITE_FILE 0x0404** a `0x20000000`; fragmentos por report 2; **JUMP_ADDRESS 0x0B0B** a `0x20000400` | ROM NXP; el cargador original firmado fue aceptado previamente con HAB CLOSED. **Sin prueba de ejecución arbitraria** |
| 4. Configuración de flash | `hj` / `ij` / `pj` / `sj` | HID report 1: parámetros little-endian; **0x11 ConfigureMemory**, **0x03 ReadMemory**, **0x05 FillMemory**, detección de tipo de chip | Cargador firmado en RAM `15A2:0073` |
| 5. Selección de destino | `lm` / `Ri` / `Qi` | Selecciona fichero firmado Bruce/Gotham según tipo de unidad; inspecciona cabecera, pie, tamaño y vector de reset | Validación **estructural del lado del PC**, **no verificación criptográfica de firma** |
| 6. Instalación | `fj` / `kj` / `lj` / `mj` / `nj` | **0x02 FlashEraseRegion** en fragmentos de hasta **16 KiB**, **0x04 WriteMemory** con report 2 de hasta **512 bytes**, y **0x0B Reset** | Cargador firmado en RAM; comprueba respuestas de estado. La ejecución posterior sigue condicionada a la cadena de arranque |
| 7. Comprobación final | `xm` / `Dj` | Reconecta en modo normal, vuelve a consultar **IN 0x81**, compara el número de build | Confirma **versión esperada**, no identidad criptográfica de cada byte ni recuperación fiable |

El código host distingue cabeceras del formato de imagen, detecta el destino por el reset handler y, si la imagen es arrancable, gestiona un bloque IVT inicial de **4096 bytes**. El programador también maneja indicadores GPR y diferentes tipos de memoria flash. No se ejecutó ninguna de esas funciones durante este análisis.

## Validaciones y fallos

- **El navegador** comprueba prefijos de números de serie (algunos rechazados), familia DVT/PVT, build y porcentaje de batería. Selecciona uno de los archivos de actualización **firmados** previstos para ese hardware.
- **La carga inicial** tiene un protocolo ROM distinto del posterior protocolo de flashloader. En SDP, los campos de comando/dirección se codifican **big-endian**; el flashloader utiliza comandos estructurados con parámetros de 32 bits **little-endian**.
- **El protocolo de memoria** responde con mensajes de estado; el JavaScript transforma estados no cero en errores. La desconexión esperada tras un salto/reinicio se trata de forma especial.
- **El lado host no comprueba la firma CMS/HAB** del archivo candidato: validar cabeceras y partición no equivale a verificar un certificado. Las comprobaciones del cargador/bootloader y la política de HAB CLOSED siguen siendo decisivas.
- **La recuperación no está demostrada** frente a interrupción de alimentación o imagen inválida. El espacio del bootloader B estaba vacío en nuestra única unidad; no debe tratarse como una copia recuperable.
- **No existe una correspondencia con el mensaje de aplicación `0x60058B68`** hallado en la fase anterior: su comparación del byte 5 no figura demostrada como receptor de estas transferencias. El actualizador de la imagen se comunica con ROM y flashloader firmado.

## Reproducción sin conexión

Guarda únicamente el JavaScript archivado como `local/app_combined.js`; **no abras la copia local en un navegador ni pulses controles de actualización**. Después:

```sh
python tools/audit_archived_updater.py local/app_combined.js --out local/host-updater.json
python -m unittest discover -s tests -v
```

El auditor verifica **tamaño y SHA-1 del objeto Git**, comprueba instrucciones de host en funciones concretas y rechaza la aparición de llamadas WebUSB Bulk nuevas. No requiere ni contiene imágenes firmadas propietarias; GitHub Actions solo usa texto de ejemplo sintético.

## Decisión del paquete A

**Sí hay una ruta física de programación prevista por el fabricante:** host → ROM SDP → **cargador firmado RAM** → comandos HID de borrado/escritura → imagen firmada → reinicio.

**No hay una ruta acreditada para ejecutar firmware propio no firmado**, ni capacidad demostrada de recuperar el mando tras un fallo. La pista del Bulk OUT del bootloader A queda **despriorizada**, no completamente descartada para funciones ajenas al actualizador archivado.

Queda **un último paquete offline acotado (B)** para comprobar la validación de imagen, el límite HAB y una posible recuperación fiable. Si no revela una vía autorizable de código propio y recuperable, aplicar la [regla de parada](puerta-decision-actualizacion.md) y pasar a un puente externo Xbox; un mando XInput para PC **no** prueba compatibilidad con una Xbox One/Series.
