# Fase 76 — Procedencia de los dos llamadores Work Queue y origen OEM del callback B

**26 de octubre de 2026.** Se ha auditado offline el firmware Bruce OEM **original firmado** SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, sin comandos USB, lectura de RAM instalada ni escrituras flash/eFuse.

Continúa los [productores de fase 75](productores-workqueue-fase75.md) y las [guardas del receptor de fase 74](recepcion-cola-original-fase74.md).

## 1. Primer productor: operación atómica previa

En el código OEM firmado, `0x6006228C BL 0x600926A0` pasa **`R0=R4+0x10`**, establecido por `0x60062288 ADD.W R0,R4,#0x10`.

La llamada está condicionada por una secuencia `LDREXB/STREXB` sobre `[R5]`. El bucle repite hasta que `STREXB` informa éxito; la comprobación del byte anterior exige que el valor previo sea cero para alcanzar el productor. Un estado diferente salta la llamada. Esto es una guarda de publicación de trabajo, **no una prueba de quién escribió el indicador**, de que el host controle `R4` o de que esa rama se ejecute físicamente.

Queda sin identificar la identidad completa del objeto `R4` y el origen de ese evento.

## 2. Segundo productor: estado condicionado

La función firmada `0x6006B290` conserva `R4=R0` y consulta `0x600D8F64`:

- Si `[R4+0x182]` es distinto de cero, no toma el envío.
- Si el retorno de `0x600D8F64` es cero, toma otra rama.
- Si el retorno no es **2**, sigue una alternativa.
- Solo bajo las guardas correspondientes, `0x6006B2AC` calcula **`R0=R4+0x11C`** y `0x6006B2B0` llama a `0x600926A0`.

La función de estado `0x600D8F64` llama a `0x600D8E6C` con argumento de selección `R1=9`. La ruta alternativa `0x600D8ED4` también utiliza `0x600D8E6C` con ese selector. Es una dependencia de estado **en el código original**, todavía no una recepción USB identificada.

## 3. Hallazgo nuevo: el puntero del segundo callback es original y se instala en código firmado

Un literal de datos del OEM en **`0x6006B4B4`** contiene el puntero Thumb **`0x6006B291`**, que corresponde a la rutina `0x6006B290`.

Más importante, las instrucciones originales firmadas hacen:

```asm
0x6006B416   LDR     R3,[PC,#0x9C]       ; carga literal 0x6006B291
0x6006B41C   STR.W   R4,[R4,#0x120]      ; contexto original
0x6006B420   STR.W   R3,[R4,#0x11C]      ; función original
...
0x6006B2AC   ADD.W   R0,R4,#0x11C
0x6006B2B0   BL      0x600926A0         ; publica objeto de trabajo si se cumplen guardas
```

Por tanto, **tenemos procedencia firmada del puntero de función del elemento B**: no es un puntero host elegido arbitrariamente en las rutas locales mostradas. Las instrucciones son anclas estáticas, no mediciones del contenido actual de RAM ni prueba de que no haya otros escritores.

Esta constatación es importante para valorar la hipótesis de ejecución propia: la llamada indirecta `BLX` del worker, identificada en fase 75, **no constituye por sí sola un mecanismo de ejecución de código no firmado**.

## 4. Conexión con la investigación USB anterior: un helper compartido, no un evento confirmado

Hemos verificado también un enlace estático entre partes investigadas en momentos distintos:

- **Fase 66**: `0x60060F2C STR.W R3,[R0,#0x90]` escribe el indicador de modo del owner; posteriormente **`0x60060F34 BL 0x6009267C`**.
- **Inicialización del objeto B**: **`0x6006B400 BL 0x6009267C`**, antes de preparar los campos de callback de `R4+0x11C`.

El destino `0x6009267C` es común a ambos fragmentos originales. **No hemos demostrado que sus argumentos se refieran al mismo objeto, que una ejecución conduzca a la otra o que el host pueda provocar una reescritura de callback**. La coincidencia acota futuras investigaciones de dependencias.

## 5. Referencias originales y resultados negativos acotados

El censo de instrucciones con forma de `BL` encuentra las dos llamadas directas a la API `0x600926A0` desde `0x6006228C` y `0x6006B2B0`. No encontró llamadas `BL` directas a la **entrada B** `0x6006B290` en la región XIP auditada, pero sí un literal Thumb exacto para esa entrada, que se utiliza en la secuencia de inicialización anterior.

La auditoría inspecciona por separado anclas conocidas de EP0/clase 10 y algunos destinos relacionados. **No establece cadena comprobada desde EP0, una interrupción USB física o una petición del ordenador hasta ninguna de las dos llamadas**. Las búsquedas `BL` directas no cubren `BLX/BX`, tablas, alias calculados ni ejecución condicionada, y no demuestran ausencia global.

## Decisión y siguiente objetivo

**Resultado fase 76:** procedencia del puntero B resuelta como **inicialización del propio firmware firmado**; guardas de A y B fijadas; puente físico USB → publicación de mensaje sigue **sin demostrar**.

La fase 77 debería intentar identificar los *objetos propietarios* de `R4` en ambas funciones y seguir las escrituras del indicador A y los estados `R4+0x182` del B, pero con criterio de parada: si no aparece un origen controlable por USB, no tratar esta Work Queue como una vía ejecutable por el host.

**Pendiente igualmente:** recepción real de mensajes, ejecución del callback, control por el ordenador, recuperación tras modificación, superación HAB CLOSED y compatibilidad nativa Xbox. Todo el trabajo presente es offline.

## Reproducir

```bash
python -m tools.audit_workqueue_caller_provenance_phase76 local/bruce.bin --out local/phase76.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_workqueue_caller_provenance_phase76 -v
```

Auditor fail-closed de firmas/anclas y comparación exacta con [evidencia JSON](../../evidence/usb-workqueue-caller-provenance-phase76.json). [PR #78](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/78).
