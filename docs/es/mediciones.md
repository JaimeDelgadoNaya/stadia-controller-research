# Mediciones y extracción

[English](../en/measurements.md)

## Unidad y evidencias

Se examinó un mando el 25 de octubre de 2026. La consulta de versión devolvió
`78 27 05 00 D5 95 02 00`: dos enteros little-endian, 337784 y 169429. El primero
es el build de aplicación; el segundo coincide con los metadatos del bootloader
extraído. Falta trazar su significado exacto en el manejador USB.

Se confirmó la secuencia USB `18D1:9400` (normal), `18D1:946B` (bootloader),
`1FC9:0135` (ROM SDP) y `15A2:0073` (cargador firmado en RAM). El propietario
realizó las pulsaciones físicas.

El comando ROM `ERROR_STATUS` (`0x0505`) devolvió un reporte 3 con `0x12343412`,
valor documentado como HAB CLOSED, y un reporte 4 con `0xF0F0F0F0` (HAB Success).
El resultado Success no significa que la configuración esté en Open.

Se contrastó el cargador original firmado conservado en dos archivos comunitarios:
SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.
También se verificaron sin conexión sus firmas y hashes. La ROM aceptó su carga
en RAM en `0x20000000`, usando el IVT `0x20000400`.

`GetProperty 0x11` devolvió estado de comando 0 y valor 1. En este cargador, la
tabla `0x20009A90` selecciona `0x20009AF0`, que llama a `0x2000A87C`. Esta función
lee `0x401F4460` y extrae el bit 1. Así se establece el significado de la propiedad
para este binario, sin deducirlo únicamente de su nombre genérico. La lectura
directa de cuatro bytes del registro fue rechazada con estado 10200.

## Extracción de flash

El identificador del MCU fue `0x006C0000` (nombre 106XA0 en la herramienta original).
La identificación de flash devolvió `0x17C8` (correspondencia original Giga-16m).

Siguiendo el método FlexSPI publicado, se cargó un FCB temporal en SRAM `0x2000`.
Las habilitaciones de comandos de modo y configuración estaban a cero. La LUT
de extracción contenía únicamente `READ 0x03` y `RDSR 0x05`, en un solo pad;
se eliminaron las secuencias de programación, borrado y habilitación de escritura.
Antes se utilizó por separado `0x90` para identificar el chip. Los registros se
accedieron mediante la interfaz permitida del cargador firmado.

Cada región de bootloader, de 128 KiB, se leyó en palabras de cuatro bytes. La
secuencia optimizada se contrastó primero con la original en seis direcciones.
Al terminar se releyeron doce palabras separadas, todas coincidentes. Las firmas
CSF y de imagen de A verificaron correctamente. B contiene exclusivamente `0xFF`.

| Región | Dirección | Bytes | SHA-256 |
|---|---|---:|---|
| Bootloader A | `0x60800000` | 131072 | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` |
| Espacio de bootloader B | `0x60820000` | 131072 | `b5a41c3758763bbec72769fab4a2533bf2db0b6312d93d25a695f9e4b9e02260` |

Hubo escrituras en RAM/SRAM y registros de periféricos, pero no comandos de
programación de firmware, borrado de flash ni programación de fusibles. Sería
incorrecto describir todo el procedimiento como «sin escrituras». RESET devolvió
éxito y después se confirmaron el modo USB normal y la respuesta de versión original.

## Límites

No es una copia completa de los 16 MB. B vacío no aporta redundancia instalada.
La verificación CMS comprueba los bloques declarados como firmados, no todos los
bytes de las regiones, y no lee por separado el hash SRK de los fusibles. No se
extrajeron toda la aplicación instalada ni la ROM. No se probaron imágenes sin
firma, modificadas, actualizaciones persistentes ni arranques con firmas inválidas.
