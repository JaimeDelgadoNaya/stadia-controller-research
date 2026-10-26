# Fase 47 — Procedencia de los escritores de callbacks EP0 y selección de adaptadores

**26 de octubre de 2026 · PR #49 · Solo análisis offline de la actualización OEM Bruce original firmada.**

## Hallazgo central: instalador dedicado para EP0 OUT e IN

**La imagen firmada sí contiene una rutina específica para registrar los dos slots EP0**, independiente de los bucles genéricos de endpoints: **`0x60054F30`**. Su primer literal original (`0x60054F74`) es el puntero Thumb **`0x60054D75`**; el segundo (`0x60054F78`) contiene el registro `0x00800040`, cuyo byte de dirección en `+2` es **`0x80` (EP0 IN)**. El código llama al registrador general en **`0x60054F4A`**, modifica ese byte de dirección a **`0x00`** en `0x60054F52`, y llama de nuevo al registrador en **`0x60054F5C`** para **EP0 OUT**. En ambos casos guarda la misma función firmada `0x60054D75` y el contexto original de entrada R1. Si el segundo intento falla, ejecuta `0x60054F68: BL 0x600D10F6` con dirección `0x80`, limpiando EP0 IN.

Existe una llamada firmada al instalador en **`0x600D0BE0`**: se alcanza estáticamente tras `0x600D0BD2: BL 0x60054F7C`, con resultado de éxito, y la comparación **`R5 == 1`**, siendo R5 un argumento de la función de control `0x600D0BC8`. El código OEM presenta además un despacho de objeto de clase en **`0x600D0BFA: BLX R3`**, tomando el método a través de dos lecturas indirectas de punteros del objeto. Su destino de clase 10 en tiempo de ejecución **no está determinado**.

La función específica de EP0 **`0x60054D74`** reconstruye bytes/campos de SETUP: carga `bRequest` en `0x60054DC4`, `bmRequestType` en `0x60054DC8`, comprueba los bits de tipo mediante `0x60054DCA: TST.W R2,#0x60` y distingue una ruta de tabla para solicitudes estándar y rutas de control adicionales que llaman a **`0x600D0BC8`** en `0x60054E50` y `0x60054E8E`.

**Por tanto, el registro específico EP0 identificado no depende de que un bucle descriptor seleccione el adaptador del evento 1.** Lo que sigue sin medirse es si esa rutina se ejecuta realmente en el mando, con qué objeto/vtable y qué clase se selecciona. Ninguna de estas funciones contiene por sí sola una prueba de instalación de punteros arbitrarios aportados por USB.

## Resultado principal

El firmware original dispone de una API firmada que registra en RAM un callback y su contexto para cada dirección de endpoint; además se han reconstruido las decisiones de los dos bucles que la llaman. Ahora sabemos **de dónde salen los punteros firmados y qué banderas hacen elegir cada adaptador**, en lugar de inferirlo únicamente de referencias literales.

**Importante:** *esto no identifica aún el callback efectivamente instalado en EP0 en un mando físico*. Los campos de los registros de endpoint y el objeto de clase se evalúan durante la configuración; la imagen de actualización no aporta una lectura de la RAM en funcionamiento.

### Registro y estructura de RAM

La función OEM **`0x600D10B8`** lee una dirección de endpoint desde `[R1+2]`, calcula:

```text
índice = 2 * (dirección & 0x0F) + ((dirección >> 7) & 1)
dirección_callback = objeto_USB + 0x0C + 12 * índice
dirección_contexto = objeto_USB + 0x10 + 12 * índice
```

Luego obtiene el callback desde `[R2]` y el contexto desde `[R2+4]`, y los escribe mediante **`0x600D10DE`** y **`0x600D10DA`**, respectivamente.

| Posición condicional | Dirección endpoint | Índice | Callback respecto a objeto | Contexto respecto a objeto |
|---|---|---:|---|---|
| EP0 OUT | `0x00` | 0 | `+0x0C` | `+0x10` |
| EP0 IN | `0x80` | 1 | `+0x18` | `+0x1C` |
| EP1 OUT | `0x01` | 2 | `+0x24` | `+0x28` |
| EP1 IN | `0x81` | 3 | `+0x30` | `+0x34` |

Las direcciones finales necesitan **el puntero base del objeto USB en RAM**, todavía no medido en el dispositivo.

### Bucles que construyen la pareja callback/contexto

**Ruta A**, función `0x60054728`: hay una llamada directa desde el código de configuración de clase **`0x600CFD92: BL 0x60054728`**. La función conserva su R0 como R6 (`0x6005472C`), extrae la dirección desde una entrada de cuatro bytes de una tabla `[R5+8]`, la guarda en `SP+6`, examina sus banderas y coloca el adaptador en `SP+0x0C` con el contexto `R6` en `SP+0x10`. Llama al registrador en **`0x60054782`**.

Las ramas originales firmadas seleccionan:

- Si `flags & 0x30 == 0x10`, adaptador **`0x600CFC53`**, evento interno 2.
- En otro caso, si `flags & 3 == 1` **y** la dirección del endpoint tiene el bit 7 activado, adaptador **`0x600CFC35`**, evento interno **1** (el que condicionalmente lleva a `bRequest`).
- En los demás casos aceptados por este bucle, adaptador **`0x600CFC71`**, evento interno 3.

**Ruta B**, llamada desde **`0x60054850`**: cuando `flags & 3 == 3` y el bit 7 de la dirección está activado, registra adaptador **`0x600CFC1B`** (evento interno 4) y el contexto R4 mediante `0x6005484C: STRD R8,R4,[SP,#0x0C]`. Cuando no cumple esos predicados, **no se llama al registrador desde esa rama particular**. No equivale a ausencia global de registro.

### Consecuencia importante para EP0

Para el **EP0 OUT (`0x00`)**, la ruta A no selecciona el adaptador del evento 1 porque la dirección carece del bit 7. Para **EP0 IN (`0x80`)**, la ruta A podría seleccionar ese adaptador si las banderas se ajustan a `(flags & 0x30) != 0x10` y `(flags & 3) == 1`.

El mismo resultado también es posible para **EP1 IN (`0x81`)**, y no está demostrado que una configuración real del firmware original contenga alguna entrada de descriptor con dirección EP0. **No hay prueba de que una petición física USB SETUP alcance la ruta de clase 10.**

### Limpieza/desregistro de slots

El firmware firmado también contiene una rutina complementaria en **`0x600D10F6`**. Reutiliza el mismo índice de endpoint, pone R2 a cero en `0x600D1120` y ejecuta **`0x600D1122: STRD R2,R2,[R3,#0x0C]`**, anulando el callback y su contexto. En `0x600D1126` pone a cero otro byte de estado de la entrada. Esta rutina acepta estructuralmente el índice 0/1, pero **no se ha probado que se ejecute para EP0 en hardware**.

El efecto depende del estado del objeto en RAM y de qué funciones de configuración/desconfiguración se invoquen. La mera existencia de escritores/limpiadores no demuestra que el ordenador pueda controlar su puntero de función.

## Qué queda sin acreditar

- Valores reales de los dos slots EP0 OUT/IN, base del objeto USB y configuración activa del mando.
- Qué registros de endpoint se crean efectivamente en un arranque real.
- Procedencia completa del objeto de clase y de su vtable durante la configuración.
- Cadena física **USB1 EP0 → adaptador evento 1 → clase 10 → manejador `0x80..0x8C`**.
- Cualquier escritura de callback arbitrario controlada por host, ejecución de código propio, bypass HAB CLOSED y compatibilidad Xbox/Switch 2.

**Próxima fase recomendada:** rastrear el origen de los registros de endpoint que consume la rutina A (`[R5+8]`), su generación a partir de la configuración firmada y la asignación efectiva de los campos del objeto USB. Si esa cadena no se puede acreditar estáticamente, el siguiente paso probatorio debería ser una lectura/observación **pasiva y recuperable**, nunca escribir firmware a ciegas.

## Reproducción

```bash
python -m unittest tests.test_bruce_ep0_slot_provenance_phase47 -v
python -m tools.audit_bruce_ep0_slot_provenance_phase47 local/bruce_pvt_a_prod_signed.bin --out local/phase47-ep0-registrar.json
```

Fuente original de actualización con SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Pruebas CI y auditoría sin conexión al mando, sin USB activo ni escrituras flash/eFuses.

[Ver PR #49](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/49).
