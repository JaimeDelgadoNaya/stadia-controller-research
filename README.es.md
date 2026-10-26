# Investigación del mando Stadia

[English](README.md) · [Español](README.es.md)

Notas de ingeniería inversa, evidencias medidas y herramientas de análisis sin
conexión para investigar la electrónica original del mando Google Stadia. El
objetivo a largo plazo es determinar si puede ejecutar firmware propio.

**Resultado actual: el arranque seguro del mando analizado está en CLOSED. No
hemos demostrado ejecución de firmware propio ni una forma de eludir las firmas.**

**[Fase #44 — identificada segunda rutina firmada que cambia el callback](docs/es/bruce-callback-secundario-escritores-fase44.md).** El OEM Bruce contiene una segunda escritura **verificada** en `0x20009EF8/FC` mediante `0x600771F6/FC`: instala el manejador **firmado `0x600DB029`** y contexto **`0x20003670`** (objeto RAM inicializado en el archivo OEM). El callback salta a un despachador de **13 códigos `0x80–0x8C`**. La cadena está acreditada **estáticamente**, pero la ejecución física, EP0 real, control del host y cualquier bypass HAB CLOSED siguen **sin demostrar**. [Evidencia](evidence/bruce-secondary-writers-phase44.json) · [PR #46](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/46).

**[Fase #43 — cadena de inicialización del callback secundario](docs/es/bruce-arranque-inicializador-fase43.md).** El nuevo barrido Thumb encuentra una llamada firmada desde código temprano (`0x6004C742`) al recorrido de una tabla de **45 inicializadores**. La entrada 21 invoca un envoltorio (`0x600748EC`) que pasa la base original **`0x200064C0`** al inicializador, el cual escribe el sentinela `0x600D4F05` en **`0x20009EF8`** y cero en **`0x20009EFC`**. **Cadena estática original verificada**, no ejecución medida en hardware: las escrituras posteriores, acceso USB externo y HAB CLOSED siguen sin resolver. [PR #45](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/45).

**[Fase #42 — inicializador firmado del callback secundario](docs/es/bruce-inicializador-callback-fase42.md).** Se identificó en código OEM original una rutina que escribe el sentinela firmado `0x600D4F05` en `base+0x3A38` y cero en `base+0x3A3C`. **Si** su base de entrada es `0x200064C0`, coincide con el callback y contexto buscados (`0x20009EF8/FC`), pero **aún no se ha demostrado ese argumento ni la ejecución de la rutina**. Se verificó también que el llamador directo localizado de un candidato de fase 41 escribe en otro objeto (`0x20015F70`). [PR #44](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/44). No hay ejecución propia, bypass HAB ni acceso físico.

**[Fase #41 — censo del callback secundario](docs/es/bruce-callback-secundario-fase41.md).** Auditoría de la imagen OEM Bruce exacta: lectura original en `0x6006140A` del puntero `0x20009EF8`, **ningún escritor directo de destino resuelto** dentro del modelo conservador; de 24 escrituras por desplazamiento, 12 son relativas a pila, 3 resuelven otra dirección y **9 conservan base desconocida**. No se demuestra valor RAM en vivo, control por USB ni ejecución propia. [Evidencia](evidence/bruce-secondary-callback-phase41.json) · [PR #43](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/43).

**[Fase #40 — callback original de clase 10 identificado](docs/es/bruce-clase10-callback-firmado.md).** Corregimos la incógnita de la fase #39: el archivo Bruce OEM firmado inicializa en RAM la entrada de clase 10 `0x200030F4` con el puntero Thumb **`0x600613FD`**, objeto inicialmente nulo y descriptor de clase 10 en `0x20003100`. El código original `0x600613FC` filtra `bRequest <= 0x7F` y para `0x81/0x83/0x84` consulta una **segunda función registrada en RAM**, todavía sin identificar en ejecución real. Resultado **offline**, sin firmware propio, bypass HAB CLOSED, USB físico ni compatibilidad probada Xbox/Switch 2. **Objetivo vigente: funcionamiento directo con la electrónica original, sin puente externo.**

**[Paquete A terminado — protocolo del actualizador WebHID/WebUSB](docs/es/protocolo-actualizador-webhid.md).** El host instala imágenes usando **ROM SDP y cargador firmado RAM**, no Bulk OUT `0x07` del bootloader A. Comandos y validaciones documentados en [la evidencia](evidence/archived-updater-host-protocol.json); sigue sin demostrarse ejecución de firmware propio. El paquete B se completó en la fase 31.

**DECISIÓN HISTÓRICA — [Fase 31: cerrar firmware interno y comenzar el puente externo](docs/es/decision-final-ejecucion.md).** El análisis offline de autenticación y recuperación ha completado el último paquete pactado. ROM HAB **CLOSED**, firmas originales válidas, sin ejecución propia autenticable ni rollback verificado. **Se detiene la investigación de modificación interna salvo nueva evidencia independiente.** Próximo paso: prototipo ESP32-S3 con BLE Stadia → gamepad Xbox 360 **para PC**, y verificación aparte de compatibilidad/autenticación de consola Xbox One/Series.

**[FillMemory verificado sobre el cargador original](docs/es/seguimiento-fillmemory-cfg.md).** La PR #27 confirmó offline que FillMemory (operación 0) llama al verificador `0x200039A8`, al igual que WriteMemory (operación 2), pero **con otra tabla de rangos permitidos**. La tabla de FillMemory no incluye los campos que habilitan Execute/Call: la escritura ordinaria sobre ellos queda descartada. Las longitudes con posible desbordamiento y los efectos de los métodos indirectos aún requieren análisis; no hay bypass HAB ni ejecución de firmware propio.

**[FillMemory: desbordamiento de 32 bits y límites del backend](docs/es/desbordamiento-fillmemory.md).** El modelo fijado al cargador original demuestra que algunos extremos calculados con desbordamiento superan dos filtros estáticos; **la comprobación dinámica y la escritura efectiva no están demostradas**. El backend recorrería una longitud enorme fuera de la región declarada; no hay firmware ejecutable ni bypass HAB.

**[FillMemory: inicialización real de la protección dinámica](docs/es/procedencia-guard-fillmemory.md).** La PR #29 verifica los cuatro valores que una función firmada escribe en el contexto del guard de rangos. Con esos valores, el modelo confirma que un extremo de 32 bits envuelto puede superar la comprobación, pero exigiría procesar aproximadamente 3,5 GiB y **no demuestra escritura efectiva, ejecución de firmware ni recuperación**. La inicialización efectiva en el mando no se ha medido.

**[FillMemory: orden de inicialización y límite virtual del backend](docs/es/arranque-primer-limite-fillmemory.md).** La PR #30 emula la rutina de llenado original en Unicorn: las longitudes envueltas entran en un bucle **byte a byte** y la CPU virtual alcanza una escritura fuera de la región declarada en `0x20020000`, sin retornar. **No es una prueba de fallo físico ni de ejecución propia.** El orden real de llamada al inicializador sigue sin verificarse.

**[Nueva investigación: Bruce OEM firmado y actualizador](docs/es/ejecucion-bruce-variantes-firmadas.md).** La PR #31 verificó tres imágenes OEM prod/stage/dev contra el archivo original: las tres tienen **idéntico código y bloque autenticado**. Las diferencias están en el material de firma, con claves de certificado distintas. Una búsqueda alineada solo encontró el puntero estructural IVT→CSF hacia el tramo posterior. El actualizador sigue usando ROM SDP y cargador RAM firmado. **No hay ejecución propia, HAB bypass ni recuperación probados.**

**[Receptores USB normales Bruce: nueva auditoría](docs/es/receptores-usb-clase-bruce.md).** La PR #32 contrastó las peticiones de clase `0x81/0x83/0x84` del actualizador archivado con el código original. Encontró ocho comparaciones literales, pero las candidatas estudiadas leen **bytes de búfer o campos de estructuras**, no un `bRequest` con origen verificado desde EP0. **Todavía no hay cadena host→receptor→ejecución propia ni recuperación fiable.**


**[Nueva fase: cadena USB SETUP → callback de endpoint en Bruce](docs/es/traza-ep0-bruce.md).** La PR #33 verifica, sobre la imagen original firmada, el vector OTG1, su trampolín a ITCM, la recepción de `ENDPTSETUPSTAT` y el despachador `0x600D0FB6` que llama al callback dinámico en `0x600D104E`. **Falta identificar la dirección realmente registrada para EP0 y el receptor de las consultas 0x81/0x83/0x84.** No hay ejecución propia ni modificación física.


**[Registro de callbacks USB en Bruce — fase #34](docs/es/registro-callbacks-ep0-bruce.md).** Se verificó en el firmware OEM original la función `0x600D10B8`, que instala en una tabla de 12 bytes las parejas función/contexto para endpoints. Se localizaron dos rutas de inicialización y cuatro funciones firmadas intermediarias de clase. **No se ha establecido cuál se registra en EP0 ni el receptor de `bRequest 0x81/0x83/0x84`**. Sin ejecución propia, sin bypass HAB CLOSED y sin escrituras en el mando.


**[Fase #35 — SETUP USB y función de clase](docs/es/setup-control-clase-bruce.md).** Análisis sobre la imagen original OEM Bruce firmada: se identificaron lecturas relacionadas de `bmRequestType`, `bRequest`, `wValue` y `wIndex`, la rama de solicitudes estándar 1–11 y el **reenvío condicional de `bRequest` por `0x600D0EB8` a un puntero de clase**. Se diferenciaron dos tablas distintas `0x60104BA4`/`0x60104BC4`; falta identificar el objeto EP0 activo y el receptor concreto de `0x81/0x83/0x84`. Sin IO sobre mando, bypass HAB CLOSED, firmware instalable ni soporte Xbox/Switch 2 demostrado.


**[Fase #36 — referencias reales de tablas USB](docs/es/bruce-referencias-tablas-clase.md).** Sobre la aplicación Bruce original firmada, se verificó que el puntero cargado en `0x6005679A` apunta a una **tabla indexada distinta**, de entradas de ocho bytes, en `0x60104BDC`. El barrido PC-relativo y `MOVW/MOVT` **no ha acreditado** una instalación de `0x600D0E58` para EP0. Quedan sin identificar la clase activa y el tratamiento de `0x81/0x83/0x84`; análisis exclusivamente offline.


**[Fase #37 — registros de clase y emulación real de SETUP](docs/es/tabla-clase-emulacion-setup.md).** **Corrección fase #38:** la base real es `0x60104B74` y hay cinco registros de 16 bytes con el selector en `+12`. El registro **`10`**, no el `4`, contiene el manejador `0x600D0E58`. Ejecutamos en Unicorn **instrucciones OEM originales** con RAM sintética: `0x81`, `0x83`, `0x84` llegan a `R1` antes del salto al callback si destinatario e interfaz coinciden; casos de error quedan rechazados. **Emulación empieza después de seleccionar evento, para antes de BX; no demuestra EP0 real, firmware propio ni bypass HAB CLOSED.**


**[Fase #38 — selección original de clase USB](docs/es/seleccion-clase-bruce-fase38.md).** Localizamos la base real `0x60104B74` en dos referencias Thumb firmadas, verificamos los cinco registros con selector `+0x0C` y emulamos la selección de identificadores `4`/`10` sin ejecutar métodos. La prueba asigna `0x600D0E58` al identificador **10**; clase activa, EP0 real y callback final siguen sin demostrar.


**[Fase #39 — procedencia del puntero del callback de clase 10](docs/es/bruce-clase10-origen-r1.md).** En el Bruce OEM original firmado se han verificado 32 instrucciones que llevan `R1` del inicializador `0x60055320` hasta una entrada **interna de 12 bytes**: `R1=[argumento_configuración_original]+12×índice`. La entrada contiene un puntero a descriptor en `+8`, salida de objeto en `+4`, y una primera palabra `+0` cuyo escritor/callback real sigue sin identificar. No existe evidencia de que el host pueda elegir ese puntero ni de ejecución propia.

## Prioridad actual: software del propio mando y Switch 2 directa

El propietario ha descartado adaptadores y placas externas. La nueva prioridad
es investigar modificación del software del Stadia para conectarlo directamente
a consolas, incluyendo **Switch 2**. [Viabilidad y objetivo mínimo](docs/es/switch2-directa.md).

Nintendo documenta soporte por cable para el Pro Controller original en Switch 2;
emular su protocolo USB es un primer objetivo condicionado a conseguir ejecución
propia en Stadia. No basta cambiar el nombre o VID/PID. El BLE de los mandos
Switch 2 usa un protocolo propietario diferente del HID BLE de Stadia.

La instrucción del propietario reabre una investigación offline acotada; no
convierte en resueltos los bloqueos técnicos de la fase 31. La reverificación
local confirma firmas originales y fallo tras mutar un byte. No hay todavía
firmware propio ejecutable, bypass HAB ni recuperación completa demostrados.

La [revisión del receptor de mensajes](docs/es/funcion-mensaje-aplicacion.md) corrige su entrada y
clasifica la etiqueta 5 como control HID de dos valores, posiblemente vibración;
no se ha demostrado que sea actualización de firmware.

La continuación añade [despacho USB con reubicación de código](docs/es/despacho-usb-aplicacion.md),
[capacidades HID medidas](docs/es/capacidades-hid.md) y
[el bloqueo inicial de Execute/Call del cargador](docs/es/puerta-ejecucion-cargador.md).
La consulta del mando fue solo de metadatos; no se enviaron informes de salida.
Estos resultados no constituyen un desbloqueo.

El trabajo histórico de interfaces externas se conserva en la
[matriz de consolas](docs/es/compatibilidad-consolas.md),
[preparación del puente](docs/es/puente-externo.md) y
[diagnóstico Windows](docs/es/diagnostico-entrada.md). No es la prioridad vigente.

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
- [Selección de aplicaciones A/B y estado de arranque — fase 12](docs/es/seleccion-aplicacion.md)
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

- **[Fase 22 — Flujo acotado de punteros USB](docs/es/flujo-punteros-usb.md)**

Análisis conservador de las 29 fuentes de alias RAM; las escrituras observadas en `+0x6C4` afectan al estado del controlador y no a los callbacks IN/OUT. Se marcan como pendientes las llamadas y ramas no seguidas.

- **[Fase 23 — Relaciones de punteros entre funciones](docs/es/alias-interprocedimental.md)**

Se verifican cuatro llamadas que transmiten el puntero global a funciones internas y las derivaciones de cuatro subobjetos con offsets distintos. No hay aún prueba de un setter de callback alcanzable desde USB ni de una vía hacia la escritura de firmware.

- **[Fase 24 — Escrituras y procedencia de punteros en funciones receptoras](docs/es/escrituras-callbacks-callee.md)**

Se revisaron cuatro funciones y la cadena de inicialización de subobjetos. Hay 23 observaciones de escrituras directas (19 sitios únicos al considerar dos bases para el mismo inicializador) y ninguna solapa los cuatro campos callback conocidos. Los valores cargados de `global+0x568/+0x570/+0x560` y pasados a `0x60809048`, además del puntero derivado de `global+0x5A8` pasado a `0x608109FE`, siguen sin resolverse.

- **[Fase 25 — Destinos de punteros dinámicos](docs/es/destinos-punteros-dinamicos.md)**

El destino `0x60809048` trabaja con un objeto de dirección desconocida y delega operaciones; `0x608109FE` desenlaza nodos de una lista mediante punteros RAM. No hay escritura sobre los callbacks USB con dirección absoluta verificada ni ruta host→flash demostrada.

- **[Fase 26 — Inicialización de punteros y cabeceras de lista](docs/es/inicializadores-punteros-listas.md)**

Dos campos (`global+0x560` y `global+0x568`) apuntan inicialmente a `global+0x134`; `global+0x570` se inicializa como **byte**, no como un tercer puntero. Se han reconstruido además dos cabeceras de lista auto-referenciales. Estado dinámico y ruta USB→flash sin demostrar.

- **[Fase 27 — Inserción de nodos y punteros del controlador](docs/es/inserciones-listas-alias.md)**

Identificadas funciones de inserción directa (`0x608109B8`) y ordenada (`0x608109D0`), con 14 transferencias estáticas verificadas. Dos llamadas calculan cabeceras desde `0x2000A7F8 + 20×índice`. No se ha demostrado una reasignación posterior de `global+0x560/+0x568`, ni acceso desde USB.

- **[Fase 28 — Procedencia de nodos e índices de listas indexadas](docs/es/procedencia-nodos-indices.md)**

En las llamadas `0x60811A32` y `0x60811E0C`, el nodo es un subobjeto `objeto+4` y el índice procede del campo `objeto+0x2C`. Las comparaciones observadas se ejecutan después de insertar; no se ha demostrado la ausencia de validaciones anteriores, un índice fuera de límites ni acceso desde USB.

- **[Fase 29 — Escrituras y límites del índice de listas](docs/es/escrituras-indices-listas.md)**

El constructor limita el índice `objeto+0x2C` a **0–15** y también inicializa `objeto+0x50`; cuatro rutas posteriores pueden copiar o actualizar el índice. No está demostrado que el límite inicial se mantenga globalmente ni que exista un índice controlable desde USB.

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
