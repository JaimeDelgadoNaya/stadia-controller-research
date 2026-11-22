# Fase 91 — Comunidad Stadia, SDP y evaluación offline de binarios

**22 de noviembre de 2026.** Continuación de la fase 90 sin modificar el mando, enviar paquetes USB/BLE, ejecutar exploits, tocar eFuses ni escribir en la flash.

## Nuevas fuentes y grado de verificación

- **Tomás / tchebb** anuncia [nxp-sdp-overrun](https://codeberg.org/tchebb/nxp-sdp-overrun) y afirma en su [hilo de Reddit del 14 de noviembre](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) que ya trabaja con firmware propio basado en Zephyr. **Es una afirmación directa del autor, no un desbloqueo reproducido aquí.** No se pudo acceder al código de Codeberg para revisarlo.
- **Stadiacast** de [jkfran](https://github.com/jkfran/stadiacast), revisión observada `9605bf461a157608b8a8756ba21fb68f7afd5ffb`, describe un servicio local que utiliza el firmware Gotham Wi-Fi `ota.282115`, incluyendo descubrimiento, GMsg, WebRTC, entradas, vibración y audio. **Resultado publicado por el autor externo**, no validado en nuestro mando.
- Los mensajes de **Fran, tchebb y Lacipe del 17/11/2026** son pruebas testimoniales de investigación comunitaria; se registran como **hipótesis de ingeniería inversa pendientes de verificar** sobre la imagen exacta.

Estos avances no prueban por sí solos una instalación segura ni un bypass general para todos los mandos en estado HAB CLOSED.

## Análisis reproducible de los dos archivos recibidos

| Artefacto | Evidencia observada | Límite de lo demostrado |
| --- | --- | --- |
| `bootloader-usb-acm.bin` | 94.248 bytes; SHA-256 `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957`. Cabecera IVT `d1 00 20 41`; entrada `0x60801000`; dirección self `0x60001000`; boot-data `0x60001020`; DCD y CSF a cero; aparecen nombres de código CDC ACM y USB Vendor. **Observación estática nueva:** una cadena de descriptores USB de 85 bytes en `0x1527c` es estructuralmente coherente y anuncia tres interfaces (Vendor 0, CDC comunicaciones 1, CDC datos 2), cinco endpoints, descriptor funcional ACM y unión CDC `1→2`; **no contiene un descriptor IAD**. Esto no acredita enumeración real ni compatibilidad con Windows. | **No** se ha verificado autenticidad, firma, corrección del descriptor, compatibilidad, ejecución o recuperación. No equivale al bootloader A original de 131.072 bytes registrado en `evidence/manifest.json`. |
| `bluetooth.bin` | 2.048 bytes y prefijo `#BONDING`. | Parece almacén privado de emparejamientos, **no firmware Bluetooth**. No se publican claves, contenido ni hash. |

Se incluye una herramienta local exclusivamente de lectura:

```sh
python -m tools.audit_community_artifacts_phase91 --bootloader /ruta/privada/bootloader-usb-acm.bin --bonding /ruta/privada/bluetooth.bin
python -m unittest tests.test_community_artifacts_phase91 -v
```

Las pruebas utilizan únicamente imágenes sintéticas. Los dos binarios recibidos permanecen fuera de GitHub. El campo de versión de la cabecera IVT **no identifica la versión HAB de la ROM**.

## El punto decisivo del Discord: ¿qué permite realmente escribir el USB Vendor?

El intercambio del 17/11 sostiene lo siguiente, aún **no demostrado sobre el binario original firmado**:

| Clave o componente | Hipótesis publicada |
| --- | --- |
| `YetiDiscoUrl` | ID 22, configurabilidad por override; mueve `RegisterController`, `DiscoverDisplay` y `ResolveDiscovery`, no GMsg ni FVC. |
| `YetiGmsgUrl` | Se consulta pero no aparece en el registro KVS de 115 entradas; los escritores oficiales no aceptarían su nombre. |
| `YetiEnvironment` | ID 21, limita el endpoint GMsg a entornos Google fijos. |
| `FirmwareVersionCheck` | Utiliza `cloudcast-pa.googleapis.com`; los overrides FVC requieren mensajes protobuf anidados. |
| Clearcut | Canal de telemetría `play.googleapis.com/log/batch`; el opt-out podría dejar un segundo emisor. |
| DNS | Fallos reiterados podrían provocar consultas directas a `8.8.8.8`. |
| `AppImageFdrVer` | ID 44. La comunidad advierte de un posible restablecimiento de fábrica: **no utilizar en pruebas**. |

La pregunta abierta de tchebb es concreta: **¿el comando USB Vendor `set KVS` exige un nombre reconocido por la tabla de registro, o invoca almacenamiento genérico de claves?** Hay que recorrer el *dispatcher*, su validación y la llamada a almacenamiento en código firmado, sin inferir capacidad a partir de nombres o trazas parciales.

Aunque `YetiDiscoUrl` fuera configurable, el canal **GMsg** sigue siendo esencial porque transporta la respuesta SDP de WebRTC. No equivale a haber sustituido todos los servidores Google.

## Próximos objetivos

1. **Auditar la procedencia exacta de `nxp-sdp-overrun`** cuando esté disponible su código: revisión inmutable, hashes, requisitos de chip/ROM, carácter temporal o persistente, fallos conocidos y riesgos de recuperación. La vulnerabilidad de U-Boot SDP divulgada por Toradex en noviembre de 2026 es distinta y no debe confundirse con este anuncio.
2. **Resolver el flujo USB Vendor → KVS** sobre la imagen original firmada y relacionarlo con los trabajos [#100](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/100) y [#102](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/102).
3. **Comparar Gotham con Stadiacast**, haciendo pruebas de red/protobuf exclusivamente sintéticas sin contraseñas reales, en la línea del [#107](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/107).
4. Mantener **NO-GO físico**: ni flashear el bootloader parcheado ni ejecutar SDP, fundir fusibles, provocar modo recuperación cortocircuitando la flash o realizar cambios con riesgo de brick en el único mando.

**Balance:** hay evidencia pública de una investigación mucho más avanzada, pero no existe aquí prueba independiente de un desbloqueo seguro en nuestro mando. El autor también pidió evitar publicar implementaciones precipitadas de su port a Zephyr y firmware Switch antes de terminar los suyos.
