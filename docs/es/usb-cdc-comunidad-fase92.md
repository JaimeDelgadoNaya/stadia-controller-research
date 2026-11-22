# Fase 92 — CDC ACM en el bootloader comunitario, revisión binaria offline

**Fecha:** 22/11/2026. **Material exacto:** `bootloader-usb-acm.bin` adjuntado por el propietario; 94.248 bytes, SHA-256 `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957`. No se ha cargado ni ejecutado este código. **No es** el bootloader A original firmado archivado en las fases anteriores.

## Hallazgos nuevos a partir de bytes concretos

Se inspeccionaron **estructuras estáticas**, sin solicitar descriptores a ningún dispositivo.

| Estructura | Offset | Resultado |
|---|---|---|
| Descriptor de dispositivo | `0xBF78` | `bLength=18`, `bcdUSB=0x0200`, clases `EF/02/01`, `VID:PID=18D1:946B`, `bMaxPacketSize0=64`, `iSerialNumber=4`, `bNumConfigurations=3` |
| Descriptor de configuración | `0x1527C` | `wTotalLength=85`, `bNumInterfaces=3`, `bConfigurationValue=1`; suma de 12 descriptores = 85 bytes |
| Interfaz 0 | Dentro de la configuración | Vendor `0xFF`; bulk `0x87` IN y `0x07` OUT, 512 bytes de máximo |
| Interfaz 1 | Dentro de la configuración | Communications/ACM `0x02/0x02`; interrupción IN `0x82` de 8 bytes |
| Interfaz 2 | Dentro de la configuración | CDC Data `0x0A`; bulk `0x81` IN y `0x01` OUT, 512 bytes |
| CDC Union | Dentro de la configuración | Subtipo `0x06`: master 1, slave 2; referencias coherentes |
| IAD | Dentro de la configuración | **0 descriptores IAD (`bDescriptorType=0x0B`)** |

El parser no encuentra discrepancias de longitud de registros, número de interfaces, número de endpoints ni referencias del CDC Union en esta configuración. Hay una combinación llamativa: clase de dispositivo `EF/02/01`, que anuncia uso de IAD, pero **la configuración de 85 bytes no incluye IAD**. Microsoft documenta la importancia de IAD y también la enumeración de colecciones CDC a través de UFD: [IAD](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-interface-association-descriptor), [colecciones CDC](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/support-for-interface-collections).

**Hipótesis, no diagnóstico:** la ausencia de IAD podría explicar dificultades de asociación automática de interfaces en algunos hosts, pero **no demuestra** por sí sola un fallo. El CDC Union presente podría ser suficiente para el controlador de clase de determinadas versiones de Windows. No se ha observado ningún evento físico de enumeración, mensaje del sistema operativo ni vinculación a `usbser.sys`.

**Otra limitación importante:** `bNumConfigurations=3` en el descriptor de dispositivo, mientras que el barrido estático encuentra una única configuración `09 02` que se pueda decodificar estructuralmente. Ello **no prueba** que las otras dos no existan: pueden crearse en RAM o proceder de otra región. La consistencia entre el descriptor solicitado por el host y la configuración activa está pendiente de captura.

## Herramienta reproducible

```sh
python -m tools.audit_usb_descriptors_phase92 /ruta/privada/bootloader-usb-acm.bin --device-offset 0xbf78 --configuration-offset 0x1527c
python -m unittest tests.test_usb_descriptors_phase92 -v
```

12 casos locales con bytes **sintéticos**, incluidos: longitudes, endpoints, unión CDC, IAD presente/ausente, desbordamientos y datos truncados. El resultado privado y depurado, sin el binario original, queda en `evidence/usb-cdc-phase92.json`. La CI ejecuta pruebas sintéticas Python 3.11/3.12.

## Próxima prueba diferenciadora — sin manipular el bootloader

1. Identificar si una **captura pasiva autorizada** de host, sobre un dispositivo ya funcional y sin flasheo, incluye la configuración completa con IAD, las tres configuraciones declaradas, y qué IDs vincula a Windows. Esta fase no realizó ninguna captura.
2. Contrastar descriptores de un **binario original firmado del mismo dispositivo y versión**. Diferencias textuales y punteros aislados no prueban que el bootloader comunitario arranque o sea seguro.
3. Mantener separada la ruta `NXP SDP overrun`: el [autor tchebb](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) comunica un exploit y un firmware Zephyr todavía inédito, pero **no hemos auditado el código del exploit** ni validado ROM, ejecución, `FIELD_RETURN` o recuperación en este hardware.
4. Mantener como asunto aparte la cuestión de la comunidad sobre `set KVS` y `YetiGmsgUrl`: requiere firmware Gotham original firmado y un recorrido real del dispatcher/almacenamiento; el archivo de bootloader parcheado **no es prueba** sobre aquel flujo. Seguimiento: [#111](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/111).

**GO:** análisis offline, tests sintéticos, cotejo de fuentes públicas y capturas pasivas seguras ya disponibles. **NO-GO:** flasheo, cambio de fusibles, ejecución de SDP, recuperación física forzada ni publicación del bonding store.
## Comparación con el dispositivo original **medido físicamente** en fase 61

Fuente primaria interna: [`evidence/usb-enumeration-phase61.json`](../../evidence/usb-enumeration-phase61.json), captura de descriptores de hub del **26/10/2026**; ver también [fase 62](../es/coincidencia-descriptores-oem-fase62.md), que fija el descriptor original en la aplicación firmada. Se compara únicamente el contenido de los descriptores, **no** sus rutas de ejecución.

| Propiedad | Aplicación OEM (hub físico, fase 61) | Candidato bootloader comunitario (archivo estático) |
|---|---|---|
| VID:PID | `18D1:9400` | `18D1:946B` |
| USB / nº configuraciones declaradas | `0x0201` / 1 | `0x0200` / 3 |
| Longitud de configuración | 80 bytes | 85 bytes |
| Interfaces | Vendor `FF` + HID `03` | Vendor `FF` + ACM `02/02` + Data `0A` |
| IAD en configuración | **2** | **0** |
| Endpoints en común | `0x87`, `0x07` | `0x87`, `0x07` |
| Índice de string de serie (no su contenido) | 3 | 4 |

El **candidato es claramente diferente del modo USB normal**. Los dos endpoints Vendor compartidos **no** demuestran un controlador, protocolo, callback o ejecutabilidad común. El resultado prueba una topología declarada en bytes, no qué devuelve la ROM o el bootloader por USB. La existencia de dos IAD en el original y cero en el candidato hace más específica la hipótesis de asociación de CDC, pero no permite asegurar un fallo de Windows.

Se añadieron **5 tests diferenciales contra la evidencia original archivada**, sumando **17 pruebas** (12 sintéticas + 5 de comparación), sin abrir hardware ni ejecutar firmware.
