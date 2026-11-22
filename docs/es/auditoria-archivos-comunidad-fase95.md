# Fase 95 — Validación de los archivos comunitarios recibidos

**Fecha:** 22 de noviembre de 2026. **Alcance:** análisis estático, lectura de documentación ajena y contraste de muestras contra los hashes existentes. No se ha conectado, reiniciado, flasheado ni interrogado ningún mando.

## 1. Archivos recibidos y clasificación

| Adjunto | Resultado |
|---|---|
| `message.txt` | Nota técnica de terceros: el comando 0xC0 pertenece al dispatcher USB de la aplicación del build 169429, no al bootloader |
| `bluetooth(1).bin` | 2.048 bytes; cabecera `#BONDING`; almacén **privado** de emparejamientos; no publicar bytes ni hash |
| `thebb_ivt_flashloader.bin` | 98.148 bytes; SHA-256 idéntico a la muestra de la fase 93 |
| `bootloader-usb-acm(1).bin` | 94.248 bytes; SHA-256 idéntico al candidato CDC de fases 91–93 |
| `bluetooth-image-public.md` | Notas detalladas del firmware Bruce, build 337784; la descripción del formato KVS permite corregir un error del analizador |
| `led-public.md` | Notas técnicas de LED: LP5562, bus LPI2C2, dirección 7-bit 0x30, canales reales rojo/ámbar/blanco, 39 patrones |
| `fwlog-kit.zip` | 15 entradas de texto, 13 módulos Python; todos compilan sintácticamente; ninguno ha sido ejecutado; contiene acciones que pueden cambiar la flash |

Los nombres, rutas y hashes no validan la autoría de los documentos. Los resultados marcados `[board]` o `[emu]` en las notas son experimentos que describe su autor, **no reproducidos por nosotros**.

## 2. Corrección decisiva del registro KVS

`bluetooth-image-public.md` señala correctamente la tabla Bruce en la dirección de flash `0x60103C58` (offset `0xC3C58` relativo al archivo enlazado a `0x60040000`), registros de 32 bytes, con **ID en +0 y puntero al nombre en +8**.

El analizador anterior empezaba en `0xC3C60`, cogía el nombre de un registro y el ID del siguiente. Se corrigió y se volvió a analizar el binario Bruce firmado exacto en CI (Python 3.11/3.12): **67 entradas, IDs 0–66**.

| Clave | ID Bruce comprobado | ID Gotham comprobado |
|---|---:|---:|
| `AnalyticsOptIn` | 20 | 23 |
| `IsDfDevice` | 22 | 25 |
| `AppImageFdrVer` | 39 | 44 |
| `BootImageFdrVer` | 40 | 45 |
| `YetiEnvironment` | ausente | 21 |
| `YetiDiscoUrl` | ausente | 22 |
| `YetiGmsgUrl` | ausente | ausente en registro |

En Bruce, `HidOverGatt` es 41, `LogToUart` es 43 y **el ID 44 es `CrashReboot`**. No confundir con el ID 44 de Gotham.

En las imágenes Gotham `ota.282115` PVT-A/PVT-B, ambas de 4.163.944 bytes, la tabla completa tiene **115 claves (IDs 0–114)** y comienza en offset `0x2C4B60`; sus bases de flash son `0x60040000` y `0x60840000`, respectivamente. La omisión de la segunda base causaba que la antigua búsqueda no encontrase la tabla de PVT-B. Con la corrección, los dos registros coinciden exactamente en las claves revisadas.

El texto ASCII `YetiGmsgUrl` aparece en ambos binarios, pero no en las 115 entradas del registro detectado. Esto **no resuelve** si el handler USB permite escribir nombres fuera del registro; solo confirma su ausencia de la tabla.

Pruebas con imágenes originales: [Gotham PVT-A/PVT-B](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45062738379) y [Bruce](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45062718753).

## 3. Nueva pista: 0xC0 pertenece a la aplicación

`message.txt` y `tools/enter_sdp.py` indican que la aplicación **build 169429**, ejecutándose normalmente desde el slot B, maneja la petición de clase dirigida a la interfaz 0 con código `0xC0` y puede saltar al ROM Serial Downloader. El autor afirma haberlo comprobado en su placa. La misma numeración enviada como petición de tipo Vendor es reconocida por la pila USB pero no procesada por ese handler.

Esto explica por qué un ACK desde el bootloader CDC no equivale a entrar en SDP: **ACK significa como mucho que la transferencia no fue rechazada**. El bootloader tiene su propio código USB y no debe suponerse que comparte los comandos de aplicación.

**Límite:** el autor documenta build 169429; Bruce 337784 es otro firmware y no conserva el mismo dispatcher `0xC0`. Ninguno de esos saltos se ha probado en nuestro mando. No enviar pruebas USB al dispositivo sobre la base de estos datos.

## 4. Auditoría del `fwlog-kit.zip`

Se inspeccionaron 15 archivos y se validó la sintaxis Python de los 13 módulos sin importarlos ni ejecutarlos. Los módulos hacen cosas diferentes:

- `vendor_bulk.py` y `fwlog.py`: gestionan los endpoints `0x07/0x87`, el desafío/desbloqueo y la recepción de registros.
- `enter_sdp.py` y `sdp.py`: contienen operaciones capaces de cambiar el estado USB y entrar en el downloader ROM.
- `sdp_load.py`: sube una imagen a RAM y solicita ejecutarla.
- `patch_flashloader.py`: modifica una entrada de la lista de rangos de lectura NOR en un flashloader (4 bytes).
- `patch_memread.py`: en un sector de 4 KB modifica **30 bytes**: 22 para cambiar la petición de lectura y 8 para alterar dos comprobaciones de dispositivo DF; después borra y reescribe el sector.
- `patch_restart.py`: altera otro sector de flash y cambia la semántica de los comandos de reinicio.
- `memread.py` y `read_nor.py`: pueden extraer memoria del dispositivo y generar archivos privados.

La propia documentación advierte que esos cambios **invalidan la firma de la aplicación**, requieren una placa que acepte imágenes modificadas y son específicos del build 169429. No se ha demostrado que funcionen en un mando de venta al público con HAB cerrado.

Precaución adicional: el comando `0x86` puede realizar un *factory reset* en el firmware sin parchear, aunque `patch_restart.py` lo redefine. Los registros internos o volcados de memoria pueden contener seriales, identificadores y datos privados. **No publicar dumps, logs completos ni el contenido de `#BONDING`.**

El ZIP hace referencia a varios documentos que **no incluye**, como `docs/usb-diagnostics.md`, `docs/enter-sdp.md`, `docs/flashloader.md` y `docs/config-fuse.md`. Sus conclusiones no sustituyen esos análisis ausentes.

## 5. LED y funciones del mando

`led-public.md` describe un LP5562 con salidas rojo, ámbar y blanco; el canal azul está desconectado en la placa del autor. Enumera 39 patrones, de los que muchos se conservan en Bruce como restos de la variante Wi-Fi. Estos datos pueden ayudar a documentar estados y diagnósticos de un firmware futuro, **no** demuestran control arbitrario de LED por USB en firmware stock.

Las notas Bruce también describen un **host USB** que interpreta entradas de Switch Pro, DualShock y DualSense, pero eso **no significa que el mando de Stadia se presente ante una Nintendo Switch o Switch 2 como Switch Pro**. Son roles USB diferentes.

## 6. Próximo paso y restricciones

El problema que merece investigación ahora es la ruta **USB Vendor → validación de nombre KVS → almacenamiento** en Gotham firmado. Tenemos los nombres e IDs correctos, pero no la comprobación de permisos ni la aceptación de claves no registradas. El diseño de un lector de mensajes de log con datos sintéticos es un camino de prueba seguro.

**NO-GO:** ejecutar las herramientas sobre un mando, desbloqueos SDP, `FIELD_RETURN`, escritura KVS, restauraciones o parches de flash sin una validación independiente del modelo/revisión, copia de seguridad y plan de recuperación. La fase 95 solo incorpora metadatos y pruebas estáticas.
