# Fase 46 — Entrega de eventos USB1/EP0 y selección del evento de clase que lee `bRequest`

**26/10/2026 · PR #48 · Auditoría sin hardware del archivo Bruce OEM original firmado, SHA-256 verificado.**

## Resultado técnico

Hemos reunido tres partes del código firmado y delimitado el enlace que falta:

1. **Candidato de interrupción USB1:** la palabra de la tabla original de vectores en offset `0x204` contiene el puntero Thumb **`0x600610D1`** para USB_OTG1 (IRQ 113). El wrapper firmado distingue varios modos; en una rama, el manejador ITCM reubicado comprueba datos de SETUP y en **`0x1258`** salta con `BL` al veneer ITCM **`0xBA68`**, cuya palabra original apunta a **`0x600D0FB7`**. **No se ha medido SCB->VTOR, el modo activo ni la ejecución del IRQ en la placa.**
2. **Despachador de eventos por endpoint:** el receptor firmado **`0x600D0FB6`** lee en `0x600D0FCA` un byte de dirección de endpoint de una *estructura de evento*, no necesariamente el paquete SETUP original. En `0x600D1010..0x600D1020` obtiene el índice `2*(endpoint&0x0F)+((endpoint>>7)&1)`, con límite de endpoint físico `0..7`. Cada entrada mide **12 bytes**: callback en base de objeto `+0x0C+12*i`, contexto en `+0x10+12*i`. En `0x600D104A` se cargan ambos y en **`0x600D104E: BLX R5`** se invoca el callback registrado. EP0 OUT corresponde a índice 0 y EP0 IN a índice 1. **Los punteros reales de esas dos entradas RAM no se han medido.**
3. **Registro de callbacks:** la función `0x600D10B8` calcula **el mismo índice** a partir del byte `[R1+2]` (estructura descriptor-like), toma `[R2]` y `[R2+4]`, y guarda puntero/contexto en `0x600D10DE` y `0x600D10DA`. Hay llamadas firmadas en **`0x60054782`** y **`0x60054850`**, que seleccionan callbacks desde los literales siguientes:

| Literal firmado | Adaptador OEM | Evento interno enviado mediante R1 |
|---|---|---|
| `0x600547A0` | `0x600CFC71` | 3 |
| `0x600547A4` | `0x600CFC35` | **1** |
| `0x600547A8` | `0x600CFC53` | 2 |
| `0x60054870` | `0x600CFC1B` | 4 |

Cada adaptador comprueba su objeto/contexto, toma la función `[[context+4]]`, conserva un puntero al evento en R2 y transfiere control mediante `BX R3`. **No basta con que un literal esté en la imagen para concluir que fue registrado en EP0.**

## Corrección: cuál de los cuatro eventos selecciona la rama de clase SETUP

Una primera hipótesis apuntaba al **evento 4**. **Era incorrecta**, y la prueba SHA-pinned la detectó: la tabla original de `0x600D0E68: TBB [PC,R1]`, tras `SUBS R1,#1`, contiene exactamente los bytes **`[27, 2, 7, 18]`** en `0x600D0E6C`.

| Evento interno R1 de entrada | Índice de tabla tras restar 1 | Destino firmado |
|---|---|---|
| **1** | 0 | **`0x600D0EA2`** — empieza la interpretación de SETUP |
| 2 | 1 | `0x600D0E70` |
| 3 | 2 | `0x600D0E7A` |
| 4 | 3 | `0x600D0E90` |

Por tanto, el **adaptador tipo 1 (`0x600CFC34`)** es el candidato relevante. Si un slot real de EP0 invoca el callback Thumb **`0x600CFC35`** con el contexto adecuado y su vtable apunta a la función de clase firmada **`0x600D0E58`**, esta última lee en `0x600D0EA2: LDR R1,[R2]` el puntero a un buffer con forma SETUP, valida receptor e índice de interfaz y carga **`0x600D0EB8: LDRB R1,[R1,#1]`**. A partir de ese momento, el paso condicional al handler de clase 10 y los códigos `0x80..0x8C` es el ya validado en fase 45.

**Distinguir el evento interno del código `bRequest` evita atribuir directamente al USB los valores 1–4 de los adaptadores.** El dato del evento que sale del receptor y el contenido del buffer original no son automáticamente el mismo objeto.

## Punto que falta para una cadena completa

La imagen firmada **sí** contiene el vector candidato USB1, el procesamiento ITCM de SETUP, el receptor de eventos con callbacks dinámicos, el registrador de endpoints y un adaptador con evento interno **1** que *condicionalmente* lleva al byte `bRequest`. **No demuestra que el endpoint 0 físico registre ese adaptador**, que su objeto tenga la vtable de clase 10, que se seleccione la clase 10 en la configuración USB real, ni que en el dispositivo esté instalado el callback secundario firmado de fase 44.

Esto no es un fallo de la herramienta: los valores de las entradas endpoint y estados de configuración se generan en RAM y no se pueden deducir simplemente de las palabras literales firmadas de la actualización. También podría existir una ruta de registro adicional no identificada por el barrido de llamadas directas.

**No se han enviado transferencias USB, alterado flash/eFuses, saltado HAB CLOSED ni ejecutado firmware propio.** El archivo OEM no es un volcado de flash instalada.

## Próxima fase (47)

Determinar **el escritor exacto y las condiciones de los dos slots EP0** y seguir el origen de la estructura de evento hasta las palabras usadas por el forwarder. Si el registro físico se confirma, verificar sin riesgo las condiciones de selección de clase 10 y sus 13 casos; en ausencia de eso, considerar otras alternativas al firmware propio.

## Reproducibilidad

```bash
python -m unittest tests.test_bruce_usb1_ep0_bridge_phase46 tests.test_bruce_ep0_slot_handoff_phase46 tests.test_bruce_event_to_brequest_phase46 -v
python -m tools.audit_bruce_usb1_ep0_bridge_phase46 local/bruce_pvt_a_prod_signed.bin --out local/phase46-usb1.json
python -m tools.audit_bruce_ep0_slot_handoff_phase46 local/bruce_pvt_a_prod_signed.bin --out local/phase46-slots.json
python -m tools.audit_bruce_event_to_brequest_phase46 local/bruce_pvt_a_prod_signed.bin --out local/phase46-events.json
```

Identidad original SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. [PR #48](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/48).
