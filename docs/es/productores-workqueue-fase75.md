# Fase 75 — Productor original de mensajes Work Queue y despacho indirecto

**26/10/2026.** Investigación offline sobre la imagen **Bruce OEM firmada original** y fijada por SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 74](recepcion-cola-original-fase74.md).

## Resultado principal

Por primera vez hemos conectado **estáticamente, mediante instrucciones OEM firmadas originales**, una ruta de publicación de mensajes con la rutina de la Work Queue cuya entrada de recepción se reconstruyó hasta `0x6D2C`.

```text
Llamador condicional 0x6006228C / 0x6006B2B0
    BL 0x600926A0                (API que utiliza WorkQueue)
    ├─ literal 0x2002014C       (objeto WorkQueue)
    ├─ [WorkQueue+0x58]         (guarda que exige estado/handle no nulo)
    └─ B.W 0x600EE18A           (productor)
         ├─ [mensaje+8] = 1     (marcador de estado)
         ├─ [SP+4] = byte 0     (tipo de elemento)
         ├─ [SP+8] = puntero al mensaje original
         ├─ R0 = [WorkQueue+0xB0] (control de cola)
         ├─ R1 = SP+4           (datos locales del elemento)
         ├─ R2 = 0xFFFFFFFF     (timeout)
         └─ BL 0x6013D0E8
              └─ veneer → ITCM 0x6A74 (rutina interna de envío)
                   └─ ruta condicional 0x6AEE BL 0xB37C
                        └─ 0xB394/0xB396 incremento/almacenamiento de contador +0x38

Consumidor WorkQueue ya identificado:
  0x600EE142 → BL 0x6013D268 → ITCM 0x6D2C (receptor)
  y, después de una eventual recepción:
  0x600EE156 LDRB R6,[SP+4]   (tipo)
  0x600EE15A LDRD R4,R0,[SP+8] (puntero al objeto y palabra siguiente)
  0x600EE15E CBZ R6,#0x600EE164
  0x600EE16E LDRD R3,R0,[R4] (método y argumento guardados en el objeto)
  0x600EE172 BLX R3            (DESPACHO INDIRECTO, NO EJECUTADO)
```

El barrido halló **cuatro literales alineados** con la dirección exacta del objeto `0x2002014C`: `0x60092698`, `0x600926B4`, `0x600926CC` y `0x6009272C`. Cuatro instrucciones candidatas de carga PC-relativa utilizan dichos literales. El código original del productor `0x600926A0` confirma la carga que lleva al mismo objeto que usa el constructor de fase 68 y el worker de fase 74.

## Pruebas sobre primitivas y control de cola

- `0x6013D0E8` es un veneer OEM firmado cuyo literal Thumb es **`0x00006A75`**, destino real ITCM **`0x6A74`**.
- Dentro de esa rutina existe una ruta condicionada que, tras comprobar capacidad (`[control+0x38]` y `[control+0x3C]`), llama a `0xB37C`; las instrucciones **`0xB394 ADDS R6,#1`** y **`0xB396 STR R6,[R4,#0x38]`** muestran cómo puede incrementarse el contador.
- Existe otra función firmada en **`0x6C88`** con contador, capacidad y escritura `0x6CEC` de `+0x38`. **La coincidencia de estructura no demuestra que sea la misma instancia**.
- El receptor **`0x6D2C`** distingue el contador en `+0x38` y, si entrega un elemento, el worker original contempla los tipos y un eventual `BLX` al método del objeto.

Estas instrucciones **son pruebas del comportamiento del código original, no de envío o entrega efectiva en un mando real**. La fase 74 mantenía una cola virtual vacía; no se ha modificado para insertar elementos ficticios ni forzar un callback.

## Posibles orígenes del productor

El censo de formas directas `BL` detecta seis llamadores de las dos API con referencias al objeto WorkQueue:

| Llamador OEM | Destino |
|---|---|
| `0x6006228C` | `0x600926A0` |
| `0x6006B2B0` | `0x600926A0` |
| `0x60060E62` | `0x600926B8` |
| `0x60062458` | `0x600926B8` |
| `0x600624D4` | `0x600926B8` |
| `0x60077386` | `0x600926B8` |

El código en `0x6006228C` toma un argumento derivado de `R4+0x10`, tras una secuencia con `LDREXB/STREXB`. El llamador `0x6006B2B0` pasa `R4+0x11C` solo si se cumplen sus guardas de estado. Estos son **orígenes estáticos de la API**, pero **no se ha demostrado el origen USB físico**, ni que procedan de EP0, ni que las guardas se satisfagan en el dispositivo.

En la imagen firmada **no aparecen literales alineados** con las direcciones Thumb de las cuatro funciones de API inspeccionadas, pero eso no descarta tablas indirectas o alias calculados.

## Valor de la fase y límites

**Qué se ha conseguido:** localizar un productor OEM para **el mismo objeto Work Queue**, reconocer su formato básico de elemento (tipo cero + puntero) y la ruta interna de envío, y vincularlo estáticamente con el despacho indirecto del trabajador. Las anclas originales se verifican de forma fail-closed.

**Qué no se ha conseguido:** ejecutar una inserción, recibir un mensaje real, llamar al callback, demostrar que una petición USB origina el elemento, modificar el puntero desde el host o ejecutar firmware propio. HAB CLOSED continúa sin bypass.

**Siguiente fase 76:** realizar un análisis de procedencia de los dos llamadores `0x6006228C` y `0x6006B2B0`, identificar sus objetos y la naturaleza de los eventos. Contrastar separadamente sus rutas con las interrupciones y solicitudes EP0 conocidas. Si no hay puente USB demostrable, no presentarlos como vía de control.

## Reproducir

```bash
python -m pip install -r requirements-emulation.txt
python -m tools.audit_queue_producers_phase75 local/bruce.bin --out local/phase75.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_queue_producers_phase75 -v
```

[PR #77](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/77) · [Evidencia estructurada](../../evidence/usb-workqueue-producers-phase75.json) · [Auditoría del firmware firmado](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40405156106).

**Sin envío de comandos USB, captura RAM física, escritura flash/eFuse ni ejecución no firmada.**
