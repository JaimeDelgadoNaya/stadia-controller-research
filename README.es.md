# Investigación del mando Stadia

[English](README.md) · [Español](README.es.md)

Notas de ingeniería inversa, evidencias medidas y herramientas de análisis sin
conexión para investigar la electrónica original del mando Google Stadia. El
objetivo a largo plazo es determinar si puede ejecutar firmware propio.

**Resultado actual: el arranque seguro del mando analizado está en CLOSED. No
hemos demostrado ejecución de firmware propio ni una forma de eludir las firmas.**

## Avances medidos

| Elemento | Resultado observado |
|---|---|
| Aplicación | Bruce **337784** (`0x52778`) |
| Bootloader A | **169429** (`0x295D5`), extraído y con firmas CMS verificadas |
| Espacio de bootloader B | 128 KiB completamente a `0xFF`; no hay segunda copia instalada |
| Identificador del MCU | `0x006C0000`, denominado **106XA0** por stadiatool |
| Identificación de flash | `0x17C8`, GigaDevice de 16 MB |
| Estado HAB de la ROM | **CLOSED**, `0x12343412` |
| Propiedad `0x11` del cargador firmado en RAM | Valor **1**, trazado hasta el bit 1 de `OCOTP_CFG5` |
| Estado final del mando | USB normal; respuesta de versión original sin cambios |

Son mediciones de **un solo mando**, realizadas el 25 de octubre de 2026. No
demuestran que todas las unidades tengan la misma configuración. Se leyó el build
del dispositivo; no se extrajo toda la aplicación instalada para comparar su hash.

## Documentación

- [Mediciones y método de extracción](docs/es/mediciones.md)
- [Cadena de arranque, actualización y cuestiones abiertas](docs/es/arranque.md)
- [Actualización del IVT y emulación ARM — fase 10](docs/es/actualizacion.md)
- [Próximos pasos y niveles de evidencia](docs/es/hoja-de-ruta.md)
- [Manifiesto de evidencias](evidence/manifest.json)
- [Créditos, procedencia y alcance de la publicación](NOTICE.md)

El nuevo análisis sigue la validación de la aplicación hasta el salto final a su
reset handler. También distingue la prevalidación estructural de las llamadas
con autenticación habilitada alrededor de una operación de actualización del
bootloader. Se documenta una observación aritmética en la comprobación de rangos
con un ejemplo reproducible sin conexión; su impacto y cualquier elusión de la
autenticación siguen sin demostrarse.

La fase 10 resuelve el callback indirecto como una comprobación de alimentación
y entrada física; también traza los argumentos fijos de 4096 bytes y la ruta de
restauración del IVT. La emulación ARM aislada de las instrucciones confirma el
ejemplo aritmético en ocho casos, sin demostrar un exploit en el mando.

## Reproducción sin conexión

Python 3.11 o posterior:

```sh
python -m venv .venv
# Activa el entorno con el comando correspondiente a tu sistema operativo.
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
```

Reproducción opcional de las instrucciones a partir de la evidencia pública, sin
un binario completo de firmware ni un mando conectado:

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_range_check.py
```

Con tu propia extracción del bootloader coincidente:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

El alias representa explícitamente el bloque IVT compartido con los primeros
4096 bytes de la imagen. La verificación CMS comprueba hashes y firmas RSA con
los certificados incluidos; **no** verifica por separado la raíz SRK de los
fusibles ni constituye una imagen completa de recuperación.

`tools/StadiaRead.cs` y `tools/Read-Stadia.ps1` permiten leer la versión en Windows
mediante una interfaz WinUSB ya instalada. Las herramientas Python anteriores
no acceden al mando, descargan archivos ni ejecutan firmware.

## Colaboración

Incluye build/hash, direcciones exactas, pasos de reproducción y si una afirmación
es medida, inferida estáticamente o hipotética. No incluyas identificadores del
dispositivo, credenciales, extracciones completas ni binarios propietarios.
Consulta la hoja de ruta bilingüe. Este repositorio documenta una investigación;
no ofrece un firmware instalable.
