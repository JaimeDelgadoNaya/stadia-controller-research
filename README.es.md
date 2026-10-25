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

- **[Traspaso completo: estado, reproducción y dónde continuar](docs/es/traspaso.md)**
- [Mediciones y método de extracción](docs/es/mediciones.md)
- [Cadena de arranque, actualización y cuestiones abiertas](docs/es/arranque.md)
- [Actualización del IVT y emulación ARM — fase 10](docs/es/actualizacion.md)
- [Almacenamiento y emulación del escritor — fase 11](docs/es/almacenamiento.md)
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


- **[Fase 12: auditoría de ruta de escritura IVT](docs/es/ruta-escritura.md)**

La **fase 12** audita una ruta de llamadas hasta el escritor físico de flash bajo
un contexto IVT construido. Comprueba instrucciones, tablas virtuales y los
argumentos fijos de 4096 bytes. **No demuestra accesibilidad desde USB**, escritura
física fuera de límites ni ejecución de firmware personalizado.

- **[Fase 13 — Superficie USB y límites del despacho](docs/es/superficie-usb.md)**

La fase 13 cuantifica qué parte del bootloader cubren las instrucciones publicadas y ofrece una inspección USB **estática, de solo lectura** para una copia local con SHA-256 verificado. No se ha identificado todavía un comando USB que permita ejecutar firmware propio.

- **[Fase 14 — USB del bootloader: interfaz de fabricante y callback](docs/es/callback-usb.md)**

Con el bootloader original del mando verificado por SHA-256 se han reconstruido **dos interfaces USB** (vendor bulk + HID) y la ruta condicional de eventos del fabricante hasta un puntero de callback en RAM. No se ha demostrado ninguna ruta de USB a escritura flash ni ejecución de firmware propio.

- **[Fase 15 — Eventos USB internos y límite de transferencia](docs/es/eventos-usb.md)**

En el bootloader original verificado se ha reconstruido una tabla de 11 eventos internos (no comandos USB de host) y un control de tamaño máximo de 512 bytes en una rutina concreta. No se ha demostrado un camino externo hacia escritura flash ni elusión de firmas.

- **[Fase 16 — Procedencia de callbacks CDC y del fabricante](docs/es/recepcion-usb.md)**

La función previamente descrita con límite de 512 bytes pertenece a una tabla de un objeto **CDC**, distinta del callback de la interfaz USB del fabricante. Se han comprobado ambas inicializaciones y sus rutas internas, pero no se ha identificado todavía un parser accesible desde Bulk OUT `0x07` ni ejecución de firmware propio.

- **[Fase 17 — Registro USB de endpoints del fabricante](docs/es/endpoints-vendor.md)**

Con el bootloader A de SHA-256 verificado hemos seguido dos registros de endpoint mediante `0x60806660`. Los endpoints Bulk OUT `0x07` e IN `0x87` utilizan índices internos distintos. Falta demostrar qué callback corresponde al OUT y cómo procesa los mensajes. No se ha demostrado un bypass de HAB CLOSED.

- **[Fase 18 — Inicialización RAM y callback Bulk OUT identificado](docs/es/inicializacion-ram-usb.md)**

El código de arranque copia los descriptores compactos de endpoints desde flash a RAM. Este flujo permite **asignar con evidencia el callback Bulk OUT `0x07` a `0x6080A06A`** y Bulk IN `0x87` a `0x60809E30`. El destino final del callback OUT y la ruta al escritor de flash siguen sin demostrarse.

- **[Fase 19 — Callbacks USB iniciales sin procesamiento](docs/es/callbacks-finalizacion-usb.md)**

Los callbacks de finalización del fabricante para Bulk IN `0x87` y Bulk OUT `0x07` se inicializan apuntando a rutinas `BX LR` que retornan inmediatamente. **No** se descarta sustitución posterior, otras rutas de actualización ni se ha superado HAB CLOSED.

- **[Fase 20 — Censo de posibles escrituras en callbacks USB](docs/es/censo-escrituras-callback.md)**

El barrido de codificaciones Thumb-2 para los campos RAM de los callbacks OUT/IN solo identifica las inicializaciones del constructor dentro del intervalo estudiado. **La ausencia de otros patrones no demuestra que no existan setters indirectos**, ni implica una ruta USB a escritura flash o un bypass HAB CLOSED.

- **[Fase 21 — Fuentes del puntero global RAM y cadena de alias](docs/es/fuentes-alias-ram.md)**

El bootloader contiene **21 literales** con el puntero global y **29 cargas PC-relativas candidatas**. Se ha verificado una ruta directa de alias hasta las inicializaciones de callbacks del constructor, **no** una sustitución posterior ni una ruta USB de escritura flash.

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
