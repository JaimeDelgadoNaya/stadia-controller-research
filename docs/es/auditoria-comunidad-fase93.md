# Fase 93 — Auditoría integral de evidencias y pruebas

**Fecha: 22/11/2026.** Esta fase contrasta las afirmaciones de las fases 91–92 con el estado real del repositorio, sus ejecuciones de GitHub Actions y las fuentes públicas nuevas. No se ejecuta firmware ni se conecta ningún mando.

## 1. Resultado de las pruebas del repositorio propio

| Grupo | Resultado | Ejecución |
|---|---:|---|
| Fase 91 — análisis de archivos privados | 10/10 por versión | Python 3.11 y 3.12 |
| Fase 92 — descriptores USB y comparación OEM | 17/17 por versión | Python 3.11 y 3.12 |
| Suite offline completa | 1.061 correctas; 35 omitidas | Python 3.11 y 3.12 |
| Carril de muestras OEM y emulación acotada | 89 correctas; 0 omitidas | GitHub Actions |
| Cinco carriles de regresión | Todos correctos | Bruce, bootloader, NXP HAB, USB HID e independent QA |

Las 35 omisiones de la suite general no son fallos; corresponden a pruebas opcionales condicionadas por muestras/fixtures. El carril separado de originales y emulación completó 89 pruebas. Los registros de Actions están enlazados en `evidence/community-validation-phase93.json`.

**Corrección documental:** el PR #110 decía inicialmente ocho pruebas para la fase 91. El archivo real contiene diez; el informe y el PR deben indicar diez.

## 2. Auditoría del firmware que ya tenemos

El binario privado `bootloader-usb-acm.bin` aparece con el mismo SHA-256 y tamaño en las fases 91 y 92. Eso confirma consistencia entre los informes, pero **no sustituye una nueva lectura de los bytes originales**: el archivo no está incluido en el repositorio y no se ha vuelto a montar en esta sesión.

El candidato no está autenticado, su CSF es nulo y no se ha probado su compatibilidad, ejecución ni recuperación. El archivo `bluetooth.bin` se mantiene clasificado como almacén privado `#BONDING`; no se publica su contenido ni hash.

La comparación USB está bien acotada: original OEM medido físicamente (`18D1:9400`, Vendor + HID, dos IAD) frente a candidato comunitario inspeccionado estáticamente (`18D1:946B`, Vendor + CDC ACM + CDC Data, sin IAD). Los endpoints `0x07/0x87` comunes no demuestran un handler compartido.

## 3. Corrección importante sobre el firmware de Tomás

En el hilo público del 14/11, Tomás afirma que su port Zephyr y firmware personalizado funcionan razonablemente bien, pero todavía no están listos para publicar. También dice expresamente que **todavía no había empezado el firmware para emular un mando Nintendo Switch**. Su shellcode de `FIELD_RETURN` se presentaba como trabajo pendiente. Fuente: [hilo del autor](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/).

Además, pidió que no se generasen versiones improvisadas de su port Zephyr ni del firmware Switch. Respetamos esa petición: esta investigación no crea un port competidor ni un clon de su firmware. El exploit de Codeberg sigue sin estar disponible para auditoría independiente en este entorno.

## 4. Stadiacast: validación externa

El upstream `jkfran/stadiacast` está en la versión **1.3.0**. Su última CI verde examinada ejecutó:

- Python 3.11: 520 correctas, 45 omitidas.
- Python 3.12: 520 correctas, 45 omitidas.
- Dependencias directas mínimas: 506 correctas, 59 omitidas.

La última ejecución visible del 22/11 figura como `action_required` y no inició jobs; no debe describirse como una CI fallida. Su suite normal utiliza `tests/fake_controller.py` y pruebas loopback, no necesita un mando físico. El receptor no modifica el firmware del mando. Esto valida el proyecto de interoperabilidad según sus pruebas, no la instalación en nuestro mando.

Se ha encontrado además un proyecto separado para un adaptador externo ESP32-S3 que emula varios mandos USB, incluido Switch Pro. No es firmware para el Stadia ni cumple el objetivo de conexión directa sin adaptador; queda registrado solo como alternativa externa.

## 5. El siguiente salto: imagen Gotham original

He localizado en `StadiaMemories/firmware` las dos imágenes públicas del firmware Wi-Fi `ota.282115`:

- [PVT-A](https://github.com/StadiaMemories/firmware/blob/main/ota.282115.stable-channel.gotham-pvt-a.214f6fe20f7b993046c77a9245c5805b056882dc.bin), 4.163.944 bytes; Git blob `e87bbd94e3843746af39c5920725e0bcf2b42c54`.
- [PVT-B](https://github.com/StadiaMemories/firmware/blob/main/ota.282115.stable-channel.gotham-pvt-b.b252d0d5a16538621abfb09609746cabc0f33292.bin), 4.163.944 bytes; Git blob `128c65d9a5b5f44d1d2a217e5c6502370958dd86`.

Repositorio fijado en commit `c86e2a397a747ce51c0988cd967142e5324ef0f9`. Aunque se ha comprobado su existencia y metadatos, los bytes no se han podido incorporar al entorno de análisis. La evidencia actual de nuestro repo corresponde a bootloader A y una muestra de actualización Bruce, **no al firmware Gotham Wi-Fi**.

Cuando se disponga localmente de una de estas imágenes, el siguiente análisis debe recorrer estáticamente el dispatcher USB Vendor, la cadena `set KVS`, el registro nombre→ID, el almacenamiento y los consumidores de `YetiDiscoUrl`, `YetiEnvironment` y `YetiGmsgUrl`. No se debe generar tráfico real ni escribir `AppImageFdrVer` (ID 44).

## Conclusión

Las pruebas automatizadas del repositorio están verdes. Las afirmaciones del Discord siguen siendo hipótesis hasta analizarlas contra Gotham. El mejor avance ahora no es flashear: es obtener la imagen exacta de Gotham y resolver el camino KVS en el firmware firmado.


## 6. Comparación directa del bootloader original con el candidato CDC

Se recuperaron y compararon los dos binarios privados `bootloader-a.bin` y `bootloader-usb-acm.bin` byte a byte.

| Dato | Original | Candidato CDC |
|---|---:|---:|
| Tamaño | 131.072 bytes | 94.248 bytes |
| SHA-256 | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` | `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957` |
| VID:PID | `18D1:946B` | `18D1:946B` |
| Interfaces | Vendor + HID | Vendor + CDC ACM + CDC Data |
| Longitud de configuración | 80 bytes | 85 bytes |
| Descriptores IAD | 2 | 0 |
| CDC Union | No | Master 1, slave 2 |

En los 94.248 bytes comunes hay **72 bytes diferentes**, agrupados en 12 intervalos. Todos quedan explicados por tres zonas:

1. **IVT:** se borra la referencia CSF original `0x60818000` (tres bytes del campo cambian).
2. **Código:** en `0xAF4E`, la instrucción Thumb pasa de `MOVS r3,#0x50` a `MOVS r3,#0x55`. El literal de puntero `0x6081527C` permanece igual. El valor cambia de 80 a 85, exactamente la longitud de la nueva configuración USB.
3. **Descriptores USB:** 68 bytes cambian para sustituir la interfaz HID por CDC ACM + CDC Data y añadir la unión CDC.

La zona de autenticación original empieza en el offset `0x18000` con cabecera CSF `D4 00 60 42`. El candidato termina en `0x17028`, antes de esa zona, y su puntero CSF es cero. Por tanto, **no conserva la cadena CSF original**. No se ha verificado la firma del original ni la aceptación HAB del candidato.

**Interpretación:** el candidato es un derivado muy cercano del bootloader A, modificado principalmente para exponer CDC ACM en lugar de HID. No es un firmware nuevo de mando ni una prueba de desbloqueo permanente. Su parecido binario no lo convierte en seguro para flashear.

Herramienta reproducible: `tools/audit_community_bootloader_patch_phase93.py`. Las pruebas de CI usan imágenes sintéticas; los hashes y resultados anteriores proceden de la comparación local de los binarios privados, que no se publican.

## 7. Segundo archivo: `thebb_ivt_flashloader.bin`

Se inspeccionó por separado otro archivo de la biblioteca:

- Tamaño: 98.148 bytes; SHA-256 `700e2cbbb884dc74a2b5d71da420350d6dca67e55f456a24f2d3ba7a69dde258`.
- IVT en offset `0x400`; entry `0x20002000`; boot data en `0x20000420`; CSF nulo.
- El boot data declara `0x18000` bytes, 156 más que el archivo recibido.
- Descriptor USB `15A2:0073`, una interfaz HID y endpoints interrupt `0x81`/`0x02`, 64 bytes.
- El binario contiene la cadena `CDC`, pero su configuración USB decodificada **no contiene una interfaz CDC ACM ni CDC Union**.

Es un artefacto separado de tipo flashloader RAM con identidad USB Freescale/NXP. Su procedencia y relación con el exploit de tchebb no están verificadas. No debe confundirse con `bootloader-usb-acm.bin`.

## 8. Tabla KVS de Bruce: evidencia de que los IDs cambian entre builds

En el binario firmado `bruce_pvt_a_prod_signed.bin` (build 337784, SHA-256 fijado en `evidence/bruce-kvs-registry-phase93.json`) se ha identificado una tabla contigua de 66 registros de 32 bytes, con IDs secuenciales 1–66.

| ID Bruce | Clave |
|---:|---|
| 21 | `AnalyticsOptIn` |
| 22 | `LastKnownSntp` |
| 23 | `IsDfDevice` |
| 24 | `UpdateGauge` |
| 25 | `OtaFromBuild` |
| 40 | `AppImageFdrVer` |
| 41 | `BootImageFdrVer` |
| 42 | `HidOverGatt` |
| 43 | `SupportNoBat` |
| 44 | `LogToUart` |

En este binario no aparecen las cadenas ASCII `YetiEnvironment`, `YetiDiscoUrl` ni `YetiGmsgUrl`. Sí aparecen `firmware_image_upload.cc`, `http_flash_writer.h`, `VendorUsbTask` y claves de actualización.

Esto **no refuta** el mapa que Fran describe para Gotham. Demuestra que los IDs y nombres del build Bruce son distintos: en Bruce, `AppImageFdrVer` es ID 40 y el ID 44 es `LogToUart`. No se debe enviar ningún ID basado en el firmware equivocado. El handler USB `set KVS` y sus permisos siguen sin estar trazados.

Herramienta: `tools/audit_bruce_kvs_registry_phase93.py`. La CI descarga el Bruce público exacto, verifica SHA-256 y analiza la tabla sin conectarse a ningún mando.

## 9. Decisión técnica actualizada

- **Confirmado:** el candidato CDC deriva byte a byte del bootloader A; los cambios de código y descriptor están acotados; elimina la referencia CSF y el bloque original de autenticación.
- **Confirmado:** el archivo `thebb_ivt_flashloader.bin` es un artefacto distinto con descriptor HID, no CDC.
- **Confirmado:** el mapa KVS de Bruce no coincide con los IDs comunicados para Gotham.
- **Pendiente:** auditar el original Gotham `ota.282115` para resolver el registro de 115 claves, el handler `set KVS` y el consumidor GMsg.
- **NO-GO:** flasheo del candidato CDC, ejecución SDP, modificación de fusibles, escrituras KVS reales o recuperación invasiva.


## 10. Comprobación de Stadiacast contra el código upstream

Se ha revisado el repositorio público `jkfran/stadiacast`, commit `9605bf461a157608b8a8756ba21fb68f7afd5ffb`, release **v1.3.0** publicada el 18/11/2026. El README declara funcionamiento extremo a extremo con el firmware Wi-Fi original `ota.282115`, sin modificar el firmware del mando.

El documento `docs/protocol.md` y el código de `config.py`/`receiver.py` corroboran la separación:

| Servicio | Host |
|---|---|
| FVC / Discovery RPC | `cloudcast-pa.googleapis.com` |
| GMsg / entrega del mensaje de señalización | `cloudcast-gmsg-prod.googleapis.com` |
| Clearcut | `play.googleapis.com` |
| SNTP | `time.google.com` |

También documenta el reenvío de `connectivitycheck.gstatic.com` y `clients3.google.com` a Google. El canal GMsg entrega el paquete de respuesta WebRTC al mando. Por tanto, los detalles de red compartidos en Discord son coherentes con el proyecto público.

**Límite:** Stadiacast demuestra interoperabilidad de red con el firmware stock; no demuestra que el USB `set KVS` admita claves arbitrarias, ni que el firmware personalizado de Tomás esté publicado o funcione en Switch 2.

Fuentes: [README](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/README.md), [protocolo](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/docs/protocol.md), [configuración](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/src/stadiacast/config.py).

## 11. Riesgo de FIELD_RETURN: NO-GO

El manual de referencia i.MX RT1060 describe el fusible `FIELD_RETURN` en `0x400[31]`: estado 0 funcional/seguro; estado 1 abierto para pruebas de devolución. Está destinado a componentes devueltos desde productos comercializados y su programación está protegida mediante CSF. La comunidad NXP confirma para RT1061 que `SEC_CONFIG_CLOSED` implica ejecutar solo imágenes autenticadas.

No hemos encontrado una fuente primaria suficiente para confirmar el mapa exacto y las consecuencias de FIELD_RETURN en el RT1061 del mando. El caso NXP de i.MX7D donde el modo de retorno dejó el dispositivo sin arrancar es de otro SoC y **no se generaliza** al RT1061; sí demuestra por qué no debe asumirse que el modo sea un desbloqueo inocuo.

**Decisión:** no leer ni programar fusibles en esta investigación. No ejecutar ningún comando de FIELD_RETURN. No se ha tocado hardware.

Fuentes: [i.MX RT1060 Reference Manual, tabla de fusibles](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf), [NXP: configuración de fusibles RT1061](https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs/1061-fuse-configuration/td-p/1705836), [NXP: advertencia FIELD_RETURN en i.MX7D](https://community.nxp.com/t5/i-MX-Processors/iMX7D-not-booting-after-FIELD-RETURN-fuse-blown/m-p/1206202/highlight/true).
