# Bruce: procedencia de peticiones SETUP y salto al callback de clase

**Actualización fase #38:** los punteros de método listados a partir de `0x60104BA4` pertenecen al registro de clase **selector 10**, cuya base es `0x60104BA4`. La tabla completa comienza en `0x60104B74` y el selector está en `+12`. La ruta de `bRequest` en `0x600D0E58` pertenece por tanto a la clase 10, no a la clase 4. [Informe verificado #38](seleccion-clase-bruce-fase38.md).


**Fase #35 · 26 de octubre de 2026 · investigación exclusivamente offline.**

## Origen de la muestra

Se trabaja con la imagen de actualización **OEM Bruce firmada**, exactamente 1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No se ha leído el hardware real ni se ha ejecutado código propio, ni se han escrito flash/RAM ni enviado paquetes USB.

La [fase #33](traza-ep0-bruce.md) llegó desde un vector USB OTG1 hasta un despachador de eventos por endpoint a través de ITCM y XIP. La [fase #34](registro-callbacks-ep0-bruce.md) verificó el registro de punteros de callback en una tabla RAM de entradas de 12 bytes, pero **no** identificó el contenido real del slot EP0.

Esta fase corrige una interpretación preliminar: un `LDRB [registro,#1]` aislado no distingue un descriptor de un SETUP. El origen de su **puntero base**, la lectura del byte `+0`, la del índice `+4` y las condiciones de despacho permiten diferenciar los casos.

## Tres rutas de análisis en código firmado

### 1. Campos de una petición SETUP: `0x600D08E8...`

Dentro del bloque iniciado en `0x600D08E8`:

| PC | Instrucción | Lectura compatible |
|---|---|---|
| `0x600D08EE` | `MOV R4,R1` | `R4` queda asociado al argumento de entrada |
| `0x600D090E` | `LDRB R3,[R4,#1]` | `bRequest` |
| `0x600D091A` | `LDRB R3,[R4]` | `bmRequestType` |
| `0x600D091C` | `ANDS R3,R3,#0x1F` | destinatario USB |
| `0x600D0922` | `LDRH R3,[R4,#2]` | `wValue` |
| `0x600D0958` | `LDRH R1,[R4,#4]` | `wIndex` |

Esta combinación es **compatible con el formato real de ocho bytes del SETUP USB**. En `0x600D0910` hay un `CMP #3` para el byte de solicitud, en un bloque con más guardas; no corresponde a la familia OEM `0x81/0x83/0x84`. Todavía hay que enlazar este argumento con la memoria efectiva donde la IRQ copió el paquete.

### 2. Tabla de solicitudes estándar de interfaz: `0x600D0D3C...`

| PC | Observación |
|---|---|
| `0x600D0D3C` | `LDR R3,[R2]`: obtiene puntero a bloque de petición |
| `0x600D0D3E–0x600D0D44` | lee byte `+0`, aplica `&0x1F` y compara con **1** (destinatario interfaz) |
| `0x600D0D4A` | lee byte `+4`, compatible con `wIndex` bajo |
| `0x600D0D50` | lee byte `+1`, **compatible con `bRequest`** |
| `0x600D0D52–0x600D0D58` | resta 1, compara con 10 y despacha mediante tabla `TBB` |

En este bloque la tabla de salto se acota a códigos de solicitud **1–11**, por lo que **esa rama no admite directamente `0x81`, `0x83` ni `0x84`**. Esta conclusión afecta únicamente a la rama identificada; **no** prueba que el firmware rechace esas solicitudes en todos sus manejadores.

### 3. Reenvío de una solicitud a un callback de clase: `0x600D0E58...`

La secuencia más relevante del firmware original es:

```asm
0x600D0EA2   LDR    R1,[R2]          ; puntero al buffer de petición
0x600D0EA4   LDRB   R3,[R1]          ; byte +0, bmRequestType
0x600D0EA6   AND    R3,R3,#0x1F     ; destinatario
0x600D0EAA   CMP    R3,#1           ; interfaz
0x600D0EAE   LDRB   R5,[R0,#0x0D]   ; índice de interfaz del objeto
0x600D0EB0   LDRB   R4,[R1,#4]      ; byte +4, wIndex bajo
0x600D0EB2   CMP    R5,R4
0x600D0EB6   LDR    R3,[R0,#4]      ; objeto/tabla de callback
0x600D0EB8   LDRB   R1,[R1,#1]      ; byte +1, bRequest
0x600D0EBA   LDR    R3,[R3]         ; puntero de función registrado
0x600D0EBE   BX     R3              ; delegación indirecta
```

Se han contrastado **estas instrucciones** con el binario original. Este bloque es compatible con un **receptor de peticiones dirigidas a una interfaz** que pasa el código `bRequest` como argumento a una función de clase ya almacenada en un objeto.

**Precisión de seguridad:** `bRequest` se pasa como **dato** (`R1`), no se interpreta directamente como dirección de salto. `BX R3` toma un puntero del objeto en RAM; **no existe evidencia** de que el host pueda elegirlo o sobrescribirlo, de una ruta a código propio ni de bypass del arranque seguro.

En la imagen estática existe un puntero Thumb **`0x600D0E59`** en la dirección de imagen XIP `0x60104BAC` (offset `0xC4BAC`). Es una palabra de datos de una tabla, **no** prueba de instalación o ejecución en el mando. Para identificar la función final habría que seguir la inicialización del objeto en `R0`, el campo `[R0,#4]` y la función apuntada por la primera palabra de esa tabla.

## Por qué otra lectura `+1` no es el mismo caso

En `0x600CFCDA`, el puntero de origen procede del **array de descriptores de endpoint**, y enseguida `0x600CFCDC` aplica `&0x30` al byte `+1`. Su contexto es la **configuración de endpoints**, no la recepción demostrada de un control SETUP.

## Continuación: tabla de callbacks e inicializadores `0x60055320/0x60055350`

En el mismo bloque de datos firmado `0x60104B88–0x60104BE0` encontramos varias direcciones Thumb contiguas:

| Palabra de datos XIP | Contenido en imagen original |
|---|---|
| `0x60104BA4` | `0x60055321` (función `0x60055320`) |
| `0x60104BA8` | `0x600D0ECB` (función `0x600D0ECA`) |
| `0x60104BAC` | `0x600D0E59` (función `0x600D0E58`) |
| `0x60104BC4` | `0x6005556D` (otra tabla posterior) |

La función `0x60055320` pasa el argumento entrante `R1` a `R6` en `0x60055324` y lo almacena con `STR R6,[R4,#4]` en `0x6005533A`, dentro de un objeto global localizado/creado por `0x60055024`. Esta instrucción evidencia un **mecanismo para instalar un puntero de callback aportado por código inicializador**. **No demuestra** que el host USB pueda escogerlo, ni que sea el mismo objeto que el utilizado en el camino `0x600D0E58`.

**Diferenciación crucial de tablas:** la función `0x60055350`, en `0x600553BA`, carga un literal almacenado en `0x600553FC`; ese literal vale **`0x60104BC4`**, **no** `0x60104BA4`. En `0x600553C0` se copia esa dirección a `[R4,#4]` y luego se invoca el primer método indirecto del nuevo objeto. Sería incorrecto atribuir esa inicialización a la tabla con `0x600D0E59` solo por proximidad.

Una búsqueda de palabras literales de 32 bits sobre la imagen firmada encontró **una** referencia a `0x60104BC4` (offset `0x153FC`), y **ninguna** a `0x60104BA4` en el barrido realizado. Es un resultado negativo acotado: podría haber referencias calculadas, tablas copiadas, constantes formadas por varias instrucciones o punteros no representados como palabras literales.

El auditor `tools/audit_bruce_class_vtable.py` comprueba estas diferencias directamente sobre el SHA original. Por ahora **no sabemos cuál es el callback de clase específico finalmente instalado**, ni si `0x81/0x83/0x84` llegan a ese objeto concreto.

## Evidencia y límites

El auditor `tools/audit_bruce_setup_verified.py` fija las instrucciones y comprueba SHA-256, además de interpretar los literales como palabras de datos. El auditor `tools/audit_bruce_control_setup.py` conserva censos y ventanas acotadas sin confundir una coincidencia lineal con un camino ejecutable. En conjunto, distinguen:

- **Sí acreditado estáticamente:** estructura compatible SETUP (bytes `+0/+1/+2/+4`), tabla de solicitudes de interfaz **1–11**, reenvío condicional de byte `+1` a un callback de clase a través de `BX R3`, con comprobaciones de destinatario e interfaz.
- **Pendiente:** comprobar que el evento procede efectivamente del paquete EP0 copiado por la IRQ, identificar qué objeto/clase está activo, la función real `[R0+4]→[puntero]` y la respuesta específica para `0x81/0x83/0x84`.
- **Sin demostrar:** ejecución arbitraria, escritura controlada, bypass HAB CLOSED, recuperación en caso de fallo, firmware instalable o compatibilidad Xbox/Switch 2.

## Próximo paso acotado

Seguir hacia atrás el **puntero de la tabla de callback de clase** utilizado por `0x600D0EB6–0x600D0EBE`. El objetivo es encontrar el inicializador firmado que establece `[R0,#4]` y su función de primer nivel; después analizar sus comparaciones de `bRequest` y límites de longitud. La separación comprobada entre las tablas `0x60104BA4` y `0x60104BC4` impide asignar erróneamente ese inicializador a la clase. Sin conectar el mando ni experimentar con comandos capaces de modificarlo.

```bash
python -m unittest tests.test_bruce_setup_verified tests.test_bruce_control_setup -v
python -m tools.audit_bruce_setup_verified local/bruce_pvt_a_prod_signed.bin --out local/setup-verified.json
python -m tools.audit_bruce_control_setup local/bruce_pvt_a_prod_signed.bin --out local/setup-census.json
python -m tools.audit_bruce_class_vtable local/bruce_pvt_a_prod_signed.bin --out local/vtable-provenance.json
```

El workflow temporal `.github/workflows/signed-app-host-boundary.yml` verifica el SHA-256 del original público, ejecuta ambos auditores y elimina los binarios temporales. Nunca se publica la imagen en el repositorio ni se efectúan escrituras sobre el dispositivo.
