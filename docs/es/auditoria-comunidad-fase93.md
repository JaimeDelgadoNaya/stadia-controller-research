# Fase 93 — Auditoría integral de evidencias y pruebas

**Fecha: 22/11/2026.** Esta fase contrasta las afirmaciones de las fases 91–92 con el estado real del repositorio, sus ejecuciones de GitHub Actions y las fuentes públicas nuevas. No se ejecuta firmware ni se conecta ningún mando.

## 1. Resultado de las pruebas del repositorio propio

| Grupo | Resultado | Ejecución |
|---|---:|---|
| Fase 91 — análisis de archivos privados | 10/10 por versión | Python 3.11 y 3.12 |
| Fase 92 — descriptores USB y comparación OEM | 17/17 por versión | Python 3.11 y 3.12 |
| Suite offline completa | 1.012 correctas; 34 omitidas | Python 3.11 y 3.12 |
| Carril de muestras OEM y emulación acotada | 89 correctas; 0 omitidas | GitHub Actions |
| Cinco carriles de regresión | Todos correctos | Bruce, bootloader, NXP HAB, USB HID e independent QA |

Las 34 omisiones de la suite general no son fallos; corresponden a pruebas opcionales condicionadas por muestras/fixtures. El carril separado de originales y emulación completó 89 pruebas. Los registros de Actions están enlazados en `evidence/community-validation-phase93.json`.

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
