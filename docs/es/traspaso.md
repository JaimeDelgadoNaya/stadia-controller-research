# Traspaso completo de la investigación

[English](../en/handoff.md)

Estado al 25 de octubre de 2026. Este documento permite continuar el trabajo sin
necesitar el historial del chat. No hay firmware propio instalable ni una vía
demostrada de ejecución de código propio.

## Objetivo original

Investigar si el mando Stadia puede ejecutar firmware propio conservando su
electrónica, con la aspiración de mejorar compatibilidad entre plataformas.
La compatibilidad directa con una consola Xbox requiere resolver además su
autenticación; no se ha implementado esa parte ni un protocolo nuevo.

## Estado comprobado

| Elemento | Resultado | Tipo de evidencia |
|---|---|---|
| Firmware instalado | Bruce 337784 (`0x52778`) | Lectura USB real |
| Bootloader A | 169429 (`0x295D5`), extraído | Lectura real y firmas CMS verificadas |
| Bootloader B | 128 KiB completamente `0xFF` | Lectura real y relecturas |
| MCU | ID `0x006C0000`, etiqueta 106XA0 | Lectura real |
| Flash | ID `0x17C8`, GigaDevice 16 MB | Lectura real |
| HAB | CLOSED, ROM `0x12343412`; propiedad 0x11 = 1 | Dos rutas de consulta reales |
| Estado final tras pruebas físicas | USB normal, misma respuesta de versión | Lectura real posterior al reinicio |
| Comprobación de rangos de imagen | Acepta un rango desbordado y cierto tamaño cero | Emulación de instrucciones originales |
| Comprobación de almacenamiento | Puede delegar fuera de partición con offset sintético | Emulación, dispositivo físico simulado |
| Ejecución propia / elusión de firmas | No demostrada | Pendiente |

Las mediciones corresponden a una unidad. La aplicación instalada no se extrajo
completa; conocer su build no equivale a verificar el hash de toda su flash.

## Qué se hizo con el mando

Se usó WinUSB ya instalado para leer la versión, y HID para diagnóstico. El
propietario realizó las combinaciones físicas hasta pasar de `18D1:9400` a
`18D1:946B` y `1FC9:0135`. Se consultó primero ERROR_STATUS de la ROM. Después
se cargó el cargador original firmado de Google exclusivamente en RAM, se
consultaron HAB y MCU y se leyó flash mediante FlexSPI con LUT temporal de lectura.

Hubo escrituras temporales en RAM/SRAM y registros FlexSPI. No se enviaron
comandos de programación de firmware, borrado de flash ni programación de
fusibles. Se extrajeron dos regiones de 128 KiB; A contiene el bootloader y B está
borrada. Se reinició por el comando del cargador y se comprobó el regreso a modo
normal con los mismos ocho bytes de versión. Las fases 9, 10 y 11 fueron offline.

## Documentos técnicos y orden recomendado

1. [Mediciones](mediciones.md): protocolos, respuestas, extracción y límites.
2. [Fase 9](arranque.md): validación de aplicación, HAB y bandera estructural.
3. [Fase 10](actualizacion.md): callback, buffers IVT y restauración.
4. [Fase 11](almacenamiento.md): descriptor 0x12, métodos y delegación emulada.
5. [Manifiesto](../../evidence/manifest.json): archivos, hashes y alcance.

## Mapa mínimo para retomar el código

Todas estas direcciones pertenecen al bootloader A build 169429 con SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.

| Dirección | Descripción de investigación |
|---|---|
| `0x60801DD4` | Flujo de actualización/selección de IVT |
| `0x60801EF0` | Salto a aplicación después de validar |
| `0x60801F5C` | Envoltorio HAB entry/authenticate_image_no_dcd/exit |
| `0x60801FE6` | Comprobación de rango de imagen; suma de 32 bits |
| `0x6080200C` | Validador de aplicación |
| `0x608020A8` | Validador de bootloader con bandera estructural/autenticada |
| `0x608022FC` | Callback de alimentación y entrada física |
| `0x6080285C` | Salto Thumb hacia ese callback |
| `0x6080AA66` | Traducción de offset de partición a offset de flash |
| `0x6080AA7C` | Comprobación offset + longitud frente a capacidad |
| `0x6080B0F0` | Escritor de partición sin cifrado |
| `0x60815300` | Tabla de métodos sin cifrado |
| `0x60815320` | Tabla del dispositivo físico |
| `0x60001000` | IVT compartido: descriptor 0x12, 4096 bytes |

Los nombres son descripciones inferidas, no símbolos originales recuperados.
`evidence/bootloader-analysis.json` conserva instrucciones, bytes, llamadas
directas, literales y tablas seleccionadas. Su decodificación usa Thumb M-class.

## Reproducción desde un clon limpio

```sh
python -m venv .venv
# Activa .venv con el comando de tu sistema.
python -m pip install -r requirements-emulation.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
python tools/emulate_range_check.py
python tools/emulate_storage.py
```

Las pruebas y ambos emuladores pueden ejecutarse con la evidencia pública,
sin mando ni binario completo. La suite completa contiene 14 pruebas. El primer
emulador verifica ocho casos de la función de rangos. El segundo verifica cuatro
invocaciones del escritor con contexto construido; intercepta el backend físico
y devuelve éxito simulado. No valida la aceptación final de la flash real.

Para analizar y verificar una extracción propia coincidente:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

El alias representa el IVT compartido mediante los primeros 4096 bytes del
archivo. La verificación comprueba hashes y firmas con certificados incluidos;
no compara por separado las claves con los fusibles SRK. Las regiones extraídas
no son una copia completa de recuperación de los 16 MB.

## Hipótesis que no deben convertirse en conclusiones

- CLOSED está medido: no asumir que cargar datos en RAM permite ejecutarlos.
- El cargador firmado de Google sí se ejecutó; no fue código propio.
- Una imagen llamada dev no implica desbloqueo: las imágenes Bruce comparadas
  comparten el contenido anterior al área final de firmas.
- B vacío es el espacio de bootloader B; no se midió el contenido de aplicación B.
- Existe restauración del IVT, pero no se demostró recuperación ante pérdida de alimentación.
- Los ejemplos de desbordamiento son reales en emulación, pero no hay una entrada
  externa demostrada que permita controlar esos parámetros en la ruta revisada.
- El escritor IVT revisado recibe offset cero y tamaño fijo 4096. Escribir fuera
  de una partición no demuestra elusión de HAB ni ejecución de código.

## Siguiente trabajo útil

1. Seguir llamadores del escritor `0x6080B0F0` y sus interfaces hasta encontrar
   qué parámetros, si alguno, pueden provenir de USB u otra entrada controlable.
2. Separar esa accesibilidad de los efectos: comprobar validaciones posteriores,
   alineación, destinos permitidos y autenticación antes de atribuir impacto.
3. Reconstruir selección de aplicación A/B y sus metadatos de intentos de arranque.
4. Solo proponer otra prueba física si hay una hipótesis concreta y recuperable.
   No se necesita flashear una imagen modificada para reproducir lo publicado.

## Material que permanece local

El repositorio público contiene herramientas, hashes y fragmentos de evidencia,
pero no imágenes propietarias completas ni identificadores personales. En el
espacio de trabajo original se conservan `outputs/bootloader-a.bin`,
`outputs/bootloader-b.bin`, el informe y ZIP de fase 8 y los scripts de extracción
en `work/`. El ZIP es un archivo local, no un release público. El propietario
puede proporcionar esos archivos a su siguiente entorno si desea repetir el
análisis del binario completo. No hay ningún proceso de extracción dejado activo.

## Fase 12 — Auditoría automatizada de llamadas al escritor IVT

Se añadió [la auditoría de ruta de escritura](ruta-escritura.md), con
`tools/trace_write_path.py` y pruebas de cambios de instrucciones, enlaces directos
y tablas virtuales. El informe usa únicamente `evidence/bootloader-analysis.json`.
Comprueba la cadena **condicionada** entre `0x6080285C` y el escritor físico
`0x60808E38`; las llamadas IVT examinadas conservan longitud fija `0x1000`
y offset cero. **No existe una ruta desde USB demostrada.** Tampoco hay
elusión de HAB o ejecución de firmware propio. Ejecutar:

```sh
python tools/trace_write_path.py
python -m unittest discover -s tests -v
```

## Fase 13 — Delimitar el despacho USB

La [fase 13](superficie-usb.md) añade `tools/audit_usb_surface.py`: cuantifica la cobertura pública (28 regiones, 2340 bytes de 131072, 67 llamadas directas, 41 destinos no cubiertos, 16 transferencias indirectas) y prepara una exploración **exclusivamente estática** de descriptores USB y puntos de entrada usando un bootloader **local** cuyo SHA-256 debe coincidir con el de la medición. Las heurísticas no demuestran existencia ni accesibilidad de un comando USB; no hay firmware propio ejecutado. Sin binario local, solo puede producir el informe de cobertura pública.

Ejecutar `python tools/audit_usb_surface.py` y `python -m unittest discover -s tests -v`. Para análisis local posterior: `python tools/audit_usb_surface.py --bootloader local/bootloader-a.bin`. No subir la imagen al repositorio.

## Fase 14 — Descriptor USB verificado y callback de fabricante

Se ha recibido un bootloader A de 128 KB cuyo SHA-256 coincide exactamente con el registrado. La [fase 14](callback-usb.md) documenta la configuración USB `18D1:946B`: interfaz 0 vendor con bulk IN `0x87`/OUT `0x07` (512 bytes) e interfaz 1 HID con interrupciones IN `0x83`/OUT `0x03` (64 bytes). Se verifica el callback `0x60809E64` con puntero inicial a función vacía en RAM, pero todavía **no** hay origen USB probado de una escritura en flash. El lector `tools/audit_usb_callbacks.py` funciona exclusivamente sobre el fichero local y produce JSON. El binario no se publica.

## Fase 15 — Despachador de eventos USB interno

El [informe de fase 15](eventos-usb.md) comprueba, sobre el bootloader A 169429 de SHA-256 conocido, la tabla `TBB` de **11 eventos internos** en `0x60809C68`, con ramas 4, 5 y 8 hacia la devolución predeterminada 1. La rutina `0x60809B28` limita a `0x200` bytes su argumento de transferencia. **No son once comandos de host**; todavía no hay traza desde Bulk OUT `0x07` hasta el escritor de flash ni vulneración de HAB CLOSED. El analizador `tools/audit_usb_event_dispatch.py` funciona offline y exige el SHA exacto. Pruebas sintéticas disponibles en `tests/test_usb_event_dispatch.py`; el binario original continúa privado.

## Fase 16 — Separación de callbacks CDC y vendor

Se ha revisado el bootloader A original con SHA-256 verificado y se ha documentado la [fase 16](recepcion-usb.md). El límite de 512 bytes en `0x60809B28` pertenece a la tabla `0x60814E18` de un objeto marcado como CDC, inicializado en `0x6080BB1C`. El callback opcional de dicho objeto se inicializa a cero y la rutina `0x60809C44` solo lo invoca cuando no es nulo. El callback del fabricante en `0x60809E64` es independiente y arranca apuntando al stub `0x60809E3D`. **No se ha reconstruido la entrada Bulk OUT `0x07` hasta un parser ni una ruta hacia escrituras flash.** Analizador offline: `tools/audit_usb_callback_provenance.py`, evidencias saneadas y pruebas sintéticas; binario privado no publicado.

## Fase 17 — Registro USB de endpoints

La [fase 17](endpoints-vendor.md) verifica la inicialización de **dos endpoints** del fabricante y el uso de dos callbacks en tabla `0x60814F24`, con llamada a registrador `0x60806660`. El registro indexa por número y dirección de endpoint (OUT `0x07` → índice 14; IN `0x87` → 15). **Queda pendiente** asociar cada callback al endpoint exacto, porque el descriptor del registro se obtiene de RAM en ejecución, y seguir el parser real de paquetes. `tools/audit_vendor_endpoints.py` verifica SHA-256 y huellas de código offline; evidencias saneadas en `evidence/usb-phase17.json`; el binario no se publica. No se han enviado comandos ni escrito flash.

## Fase 18 — Identificación del callback Bulk OUT por inicialización RAM

El [informe fase 18](inicializacion-ram-usb.md) verifica en el bootloader A SHA-256 conocido la copia de **400 bytes** de flash `0x608161E0` a RAM `0x20000000` durante el arranque normal. Esa copia contiene `87 02 00 02` en `0x200000D8` y `07 02 00 02` en `0x200000DC`. Combinando la rutina de registro y tabla de callbacks de fase 17 se demuestra en ese flujo que **Bulk IN `0x87` -> `0x60809E30` y Bulk OUT `0x07` -> `0x6080A06A`**. El segundo reenvía a `0x6080A062`, cuyo destino final es indirecto y aún no está resuelto. Script offline: `tools/audit_endpoint_ram_init.py`; evidencia saneada `evidence/usb-phase18.json`; pruebas sintéticas. **No se ha ejecutado código propio ni superado HAB CLOSED.**

## Fase 19 — Destinos por defecto de los callbacks USB

[Análisis de fase 19](callbacks-finalizacion-usb.md): siguiendo `0x60806554` → `0x6080A06A` → `0x6080A062`, el constructor del objeto vendor (RAM `0x20009160`) inicializa el puntero de finalización de OUT `0x07` (`0x20009178`) con `0x6080AFFD` Thumb, función `0x6080AFFC`, y el de IN `0x87` (`0x20009170`) con `0x6080AFFB`, función `0x6080AFFA`. **Ambas instrucciones son `BX LR`, sin procesamiento en ese estado inicial.** Los contextos `0x2000917C` y `0x20009174` se inicializan a cero. Esto **no** excluye modificaciones posteriores de callbacks ni otras rutas USB; todavía no se demostró escritura flash desde host, elusión HAB ni firmware propio. Herramienta SHA-locked: `tools/audit_vendor_completion.py`; evidencia `evidence/usb-phase19.json`; tests sintéticos.

## Fase 20 — Censo de escrituras candidatas a callbacks USB

El [informe fase 20](censo-escrituras-callback.md) verifica en el bootloader privado build 169429 un barrido **limitado** de codificaciones `STR.W Rt,[Rn,#imm12]` en `0x60801000..0x60814F00` (final exclusivo). Para offsets globales `+0x5F8/+0x5FC/+0x600/+0x604` solo se reconocen los cuatro `STR.W` del constructor `0x6080BB50/+0xBB6C/+0xBB5A/+0xBB70`. No se encontraron literales de punteros absolutos alineados a los campos RAM. El intervalo vendor `0x60809E24..0x6080A076` tampoco tiene candidatos `STR` Thumb16 o `STR.W` Thumb-2 de offset positivo `+0x10/+0x14/+0x18/+0x1C`. **Esto NO descarta setters por alias, STRD/STM, offsets calculados, otras regiones o rutas distintas.** Auditor `tools/audit_callback_writers.py`; pruebas sintéticas `tests/test_callback_writers.py`; evidencia `evidence/usb-phase20.json`. Sin acceso al mando, código propio ni elusión HAB CLOSED.

## Fase 21 — Origen de alias al objeto global RAM

La [fase 21](fuentes-alias-ram.md) identificó **21 literales alineados** que contienen `0x20008B78` y **29 cargas PC-relativas Thumb candidatas** que los referencian. El paso `0x6080C0B2` (`LDR R0,[PC,#8]`) → `0x6080C0B4` (`BL 0x6080BAC0`) → `0x6080BAC4` (`MOV R4,R0`) demuestra una cadena estática hasta las cuatro escrituras de inicialización de callbacks/contextos del constructor. Los usos de `0x60809E6A` y `0x60809EB8` son lecturas de otros campos. **No se ha demostrado un setter posterior, entrada USB al escritor ni bypass de HAB CLOSED.** Herramienta offline: `tools/audit_global_alias_sources.py`; tests sintéticos y `evidence/usb-phase21.json`. Los 29 sitios son candidatos de instrucción, no todas rutas alcanzables.

## Fase 22 — Seguimiento acotado de alias

[Documentación fase 22](flujo-punteros-usb.md). El nuevo `tools/audit_alias_dataflow.py` sigue como máximo 96 bytes por cada uno de los 29 orígenes de punteros RAM, deteniéndose en llamadas, ramas o retornos. Las escrituras observadas en `0x60809790` y `0x60809842` afectan al estado `global+0x6C4`, no a los callbacks `+0x5F8/+0x600`. El análisis no descarta vías indirectas ni demuestra una ruta de entrada USB hasta la flash. Las pruebas sintéticas y `evidence/usb-phase22.json` están en la rama; el binario original sigue privado.

## Fase 23 — Alias interprocedimentales verificados

La [fase 23](alias-interprocedimental.md) identifica cuatro llamadas `BL` que reciben el objeto global RAM `0x20008B78`: `0x6080C0B4` → constructor `0x6080BAC0`, `0x60802504/0x60808138` → servicio `0x6080B218` y `0x6080FB4C` → `0x6080B17C`. Esta última función preserva la base en R4 y prepara llamadas con los offsets `+0x568/+0x560/+0x630/+0x578`. El servicio `0x6080B218` crea `global+0x630`, salta a `0x60809ABC` y prepara `global+0x644` para otra llamada. El auditor `tools/audit_interprocedural_aliases.py` verifica las instrucciones, literales y destinos, con pruebas sintéticas y `evidence/usb-phase23.json`. **No se ha demostrado un setter posterior ni alcanzabilidad desde USB**, y no se ha conectado el mando.

## Fase 24 — Escrituras y punteros en funciones receptoras

La [fase 24](escrituras-callbacks-callee.md) revisa los cuatro destinos de la fase 23 y la cadena auxiliar desde `0x60809D98`. Se documentan 23 observaciones de store (19 sitios de instrucción únicos porque `0x6081099C` se analiza con dos offsets de entrada), ninguna solapada con los callbacks `global+0x5F8/+0x5FC/+0x600/+0x604`. La ruta `global+0x58C → 0x60810210 → 0x60810BB8 → 0x60810B38` inicializa campos hasta `+0x5D8`; `0x60811DC8` lee un puntero desde `global+0x5A8` y lo pasa, derivado, a `0x608109FE`. Ese destino dinámico y las rutas por `0x60809048` (valores cargados de `global+0x568/+0x570/+0x560`) siguen pendientes. Herramienta offline `tools/audit_callee_store_provenance.py`, pruebas sintéticas y `evidence/usb-phase24.json`.

## Fase 25 — Dos destinos de punteros dinámicos

La [fase 25](destinos-punteros-dinamicos.md) desensambla `0x60809048` (objeto de entrada opaco, lecturas `+0x154/+0x158/+0x15C`, argumentos derivados y llamadas auxiliares) y `0x608109FE` (desenlazado de lista: escrituras a `anterior+8`, `siguiente+4`, `propietario+4`, `nodo+0x10` y contador de propietario). La entrada a la segunda función desde `0x60811DC8` deriva nodos `link+0x18` y `link+4` tras cargas de punteros dinámicos. No se ha demostrado que los objetos recibidos coincidan con los campos callback `0x20009170/74/78/7C`, ni host→flash o bypass HAB. Auditor SHA-locked `tools/audit_dynamic_pointer_sinks.py`, tests sintéticos y evidencia `evidence/usb-phase25.json`.

## Fase 26 — Origen de los punteros y listas

La [fase 26](inicializadores-punteros-listas.md) demuestra estáticamente que el constructor en `0x6080BAE2` calcula `global+0x134 = 0x20008CAC` y lo guarda en `global+0x560` y `global+0x568` (`0x6080BAEC`/`0x6080BAF2`). **Corrección:** `global+0x570` se inicializa con `STRB.W` a un **byte cero**, no está probado que sea otro puntero. En la rama indicada se llama dos veces a `0x6081099C` para crear cabeceras en `global+0x59C/+0x5B0`, con conteo cero y enlaces auto-referenciales (el valor `0xFFFFFFFF` es un marcador). Esta es una reconstrucción del **estado inicial**, sin observación RAM en vivo ni prueba de ausencia de cambios posteriores. Auditor `tools/audit_pointer_initializers.py` y evidencia saneada `evidence/usb-phase26.json`.

## Fase 27 — Funciones de inserción y listas indexadas

[Informe fase 27](inserciones-listas-alias.md). El análisis del bootloader A SHA-256 verificado identifica `0x608109B8` como inserción directa en lista doblemente enlazada (9 `BL` comprobados) y `0x608109D0` como inserción condicionada por clave (4 `BL` y 1 salto `B.W` comprobados). Dos llamadores de `0x608109B8` calculan `R0 = 0x2000A7F8 + 0x14×índice` mediante `MLA`; es una base distinta de las cabeceras iniciales `0x20009114/0x20009128`. El censo muy limitado de `STR.W` Thumb-2 inmediatos con offsets `+0x560/+0x568` sigue encontrando solo las dos escrituras del constructor; **no demuestra ausencia de reasignaciones por alias**. Script offline `tools/audit_list_insertion_paths.py`, pruebas sintéticas y `evidence/usb-phase27.json`. Sin ruta externa USB→flash ni elusión HAB CLOSED demostrada.

## Fase 28 — Procedencia de nodos e índices

El [informe de fase 28](procedencia-nodos-indices.md) demuestra estáticamente dos rutas hacia inserción directa `0x608109B8`: en `0x60811A32`, el nodo es `R6+4` e índice `[R6+0x2C]`; en `0x60811E0C`, nodo `R4+4` e índice `[R4+0x2C]`. La base de cabeceras se obtiene con `MLA`: `0x2000A7F8 + 20×índice`. Las comparaciones relacionadas con el índice en `0x60811A3C` y `0x60811E18` aparecen **después** de las inserciones; no se ha identificado un guardia de límites en los tramos previos seleccionados. Eso **no prueba** que faltara validación en llamadores o constructores, ni acceso fuera de límites o índice controlable desde USB. Auditor privado SHA-locked `tools/audit_bucket_node_provenance.py`, pruebas sintéticas y evidencia saneada `evidence/usb-phase28.json`.

## Fase 29 — Escrituras de `objeto+0x2C` y límites

[Informe fase 29](escrituras-indices-listas.md). En el intervalo `0x60811400..0x60812200`, se verifican cinco escrituras Thumb16 `STR` a `objeto+0x2C`: `0x608115A0` (constructor: `CMP R6,#15`, `IT HS`, `MOVHS R6,#15`), `0x60811F90/0x60811FB2` (copia del campo `+0x2C` de otro objeto alcanzable mediante el puntero global `0x2000A7EC`), `0x60812056` (restauración desde propio `+0x50`) y `0x608120D6` (máximo sin signo del argumento y `+0x50` en el tramo local). El constructor también guarda el índice inicial en `+0x50` mediante `STRD` en `0x608115A2`. **Solo se demuestra un límite inicial 0–15, no un invariante global.** Auditor SHA-locked offline `tools/audit_bucket_index_writers.py`, tests sintéticos y `evidence/usb-phase29.json`. No se ha demostrado índice fuera de límites, acceso USB→flash ni bypass HAB.

## Nueva prioridad tras fase 29 — detener o continuar

**[Puerta de decisión](puerta-decision-actualizacion.md).** El objetivo deja de ser seguir indefinidamente alias ARM. El protocolo USB real de la herramienta web de actualización archivada debe enlazarse con un receptor y validaciones HAB/almacenamiento del firmware pertinente. El bootloader A no representa necesariamente todo el código USB de la aplicación ni la ROM/cargador firmado en RAM. El archivo privado `bruce_pvt_a_prod_signed(1).bin` (1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`) se ha inspeccionado como imagen candidata firmada: SP `0x2002B828`, reset Thumb `0x60040501`, posible rutina de solicitudes host en `0x60058B68`, comparación del primer byte del búfer con 5, llamada a `0x60058AA8`. No hay prueba todavía de que sea bRequest USB, una actualización alcanzable ni identidad byte a byte con el firmware instalado. **Máximo dos paquetes offline y parada obligatoria** si no hay entrada host, ejecución autorizable y recuperación fiables. Fallback: puente externo (un dongle PC XInput no implica compatibilidad con Xbox Series/One). Auditor `tools/audit_signed_app_surface.py`, evidencia `evidence/application-surface-gate.json`.

## Paquete A completado — mecanismo host real

[Informe del actualizador archivado](protocolo-actualizador-webhid.md). El JS original de `hazrpg/stadia-flasher` (`controller/app_combined.js`, Git blob SHA-1 `3c877738c12e7d5750714cd0770935ad39bd9990`, 149.810 bytes) usa **WebUSB** solo para versión/batería en modo normal (`0x81/0x83/0x84`); las imágenes se instalan por **WebHID** en la ROM NXP `1FC9:0135` y el **flashloader firmado RAM** `15A2:0073`. ROM SDP carga el flashloader firmado con `WRITE_FILE 0x0404` y salta con `JUMP_ADDRESS 0x0B0B`. El cargador firmado usa `ConfigureMemory 0x11`, `EraseRegion 0x02` (hasta 16 KiB), `WriteMemory 0x04` (hasta 512 B por report HID), y `Reset 0x0B`. El navegador comprueba metadatos y selecciona fichero, **no verifica firmas criptográficas**. La cadena de arranque HAB CLOSED sigue siendo crítica. El firmware no se envía al Bulk OUT `0x07` del bootloader A en este JS. Auditor sin ejecutar JS `tools/audit_archived_updater.py`; evidencia `evidence/archived-updater-host-protocol.json`. **Queda un único paquete B offline** para verificar aceptación/recuperación y después aplicar parada obligatoria si no hay ejecución propia recuperable demostrada.

## Fase 31 — CIERRE de la vía interna

[Decisión final autenticación/recuperación](decision-final-ejecucion.md). Con ambas investigaciones acotadas terminadas, la cadena host WebHID→flashloader firmado funciona para imágenes previstas, pero no aporta código propio autenticable en HAB CLOSED. Se volvió a comprobar en privado firmas RSA/CMS y digest de bootloader A y Bruce, y un cambio de un byte en copia temporal invalida la verificación. El bootloader A valida antes de saltar; el slot B continúa vacío en mediciones previas; falta copia integral y rollback. **STOP modificación interna, GO puente ESP32-S3 Stadia BLE→PC Xbox 360 como prototipo reversible; estudiar aparte interfaz Xbox real autorizada.** Script `tools/audit_final_auth_recovery.py`, evidencia `evidence/phase31-final-auth-recovery.json`. Reabrir solo ante evidencia nueva de ejecución propia autorizada y recuperación real.

## Investigación directa reabierta por el propietario

El propietario pide modificación del software del mando, sin dispositivos
externos, e incluye Switch 2. Esto sustituye la prioridad de puente externo,
pero no los resultados de HAB/firma/recuperación de la fase 31. La nueva revisión
es offline y acotada al receptor de mensajes de la aplicación y a requisitos
USB/BLE. Ver [Switch 2 directa](switch2-directa.md). No se ha flasheado el mando.

## Continuación: despacho USB y puerta de ejecución del cargador

La lectura HID actual declara salida ID5 de cinco bytes, dos valores de 16 bits;
coincide con el descriptor histórico y con el parser de control de vibración.
Ver [capacidades medidas](capacidades-hid.md),
[despacho de la aplicación](despacho-usb-aplicacion.md) y
[puerta Execute/Call del cargador](puerta-ejecucion-cargador.md).
La tabla del cargador está en RAM y sus entradas iniciales desactivadas no prueban
que sea inmutable. El análisis de política y fragmentos USB excluye el parcheo
directo por WriteMemory de esas entradas, incluido el intento de provocar una
vuelta aritmética mediante una longitud total enorme en esas direcciones.
Ninguna de estas observaciones demuestra ejecución propia o Switch 2 funcional.
