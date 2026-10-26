# Fase 44 — Segunda escritura firmada del callback de clase 10 y mapa de comandos

**26/10/2026 · PR #46 · Análisis exclusivamente offline de la imagen OEM Bruce original firmada.**

## Descubrimiento principal

El código original contiene una **segunda rutina de registro** que escribe en los mismos campos RAM inicializados al arrancar (fase 43). El resultado ya no depende de una coincidencia de desplazamientos: **los literales firmados acreditan la dirección absoluta de la base y el valor del puntero instalado**.

| Instrucción original | Interpretación |
|---|---|
| `0x600771EE: LDR R3,[PC,#0xF4]` | Carga de `0x600772E4` la base RAM **`0x200064C0`** |
| `0x600771F0: LDR R1,[PC,#0xF4]` | Carga de `0x600772E8` el puntero OEM Thumb **`0x600DB029`** |
| `0x600771F2: MOVW R2,#0x3A38` | Desplazamiento de callback |
| `0x600771F6: STR R1,[R3,R2]` | Escribe **`0x600DB029`** en **`0x20009EF8`** |
| `0x600771F8: MOVW R2,#0x3A3C` | Desplazamiento de contexto |
| `0x600771FC: STR R4,[R3,R2]` | Escribe el objeto `R4` en **`0x20009EFC`** |

El callback `0x600DB029` es una función de la imagen OEM firmada, no código suministrado por USB. Empieza en `0x600DB028: B.W 0x60077360`.

### Procedencia del objeto/contexto

La secuencia firmada contiene una llamada directa en `0x6005124C` a la función de registro `0x60077140`, **inmediatamente después** de `0x60051248: BL 0x60077138`.

`0x60077138` ejecuta `LDR R0,[PC,#0]; BX LR`: el literal en `0x6007713C` contiene **`0x20003670`**. La función receptora conserva R0 mediante `0x60077144: MOV R4,R0`; R4 es el valor que luego coloca en el campo de contexto.

El objeto `0x20003670` está **dentro de la copia inicializada RAM** `0x20002740..0x20003FD8`. Su primera palabra procede del offset OEM firmado `0xFE4D8` y vale **`0x600D5637`**; las 11 palabras siguientes del fragmento examinado son cero en esa *instantánea inicial del archivo*. Esto no es un volcado ni una medición de RAM en ejecución.

La rutina `0x60077140` presenta comprobaciones y saltos condicionales antes de la pareja de escrituras: **no se ha probado que la rama se ejecute en un mando real**. El censo Thumb de medias palabras encontró el llamador directo `0x6005124C`, pero no un llamador directo del envoltorio `0x60051240`. Esto **no descarta** invocación mediante puntero o tabla.

## Despachador original de 13 códigos

El callback firmado redirige a `0x60077360`, donde `SUBS R1,#0x80`, `CMP R1,#0x0C` y `TBB [PC,R1]` seleccionan **13 destinos internos**. La tabla de bytes y cuatro instrucciones clave se han anclado en la imagen original.

| Código R1 antes de restar 0x80 | Destino OEM firmado |
|---|---|
| `0x80` | `0x60077382` |
| `0x81` | `0x60077392` |
| `0x82` | `0x6007739C` |
| `0x83` | `0x600773A4` |
| `0x84` | `0x600773AE` |
| `0x85` | `0x600773BA` |
| `0x86` | `0x600773C2` |
| `0x87` | `0x600773E0` |
| `0x88` | `0x60077406` |
| `0x89` | `0x60077420` |
| `0x8A` | `0x60077434` |
| `0x8B` | `0x60077494` |
| `0x8C` | `0x6007749A` |

**No está confirmado que R1 venga de una petición USB EP0 real.** Los trece casos son el comportamiento del código **si** ese callback es invocado. Tampoco se ha demostrado que ninguno permita escribir punteros arbitrarios o ejecutar código propio.

## Censo de escrituras y corrección de límites previos

Un barrido Thumb-2 por cada dirección de media palabra de la zona XIP original y el ITCM reubicado reconoció **2625 instrucciones MOVW** sobre 2648 codificaciones prefiltradas; cinco llevan exactamente los desplazamientos `0x3A38/0x3A3C`.

- `0x60061404` y `0x60061410`: **lectura** de callback/contexto desde la función de clase 10.
- `0x60073CEA`: construcción del desplazamiento durante **inicialización con sentinela** `0x600D4F05`.
- `0x600771F2` y `0x600771F8`: construcción de desplazamientos antes de la **segunda pareja de escrituras** firmadas.

Esto **no es un censo exhaustivo de todas las escrituras de memoria**: otras rutas pueden usar `MOVT`, `ADD.W`, literales, punteros indirectos, DMA u objetos pasados entre funciones. Tampoco prueba cuándo se instala el manejador posterior ni su alcanzabilidad por el host.

## Decisión y siguiente fase

La imagen original contiene una **vía OEM concreta de sustitución del callback predeterminado por otro callback firmado**, con contexto procedente de una dirección RAM fija. La fase 45 debe trazar la activación real del llamador `0x60051240`, el puente desde USB EP0 a los parámetros del despachador y las semánticas de las 13 rutas. Si no aparece una entrada controlable, no atribuir una vulnerabilidad a la mera existencia de `BLX`.

**No se ha demostrado ejecución propia, modificación de la firma HAB CLOSED, recuperación segura ni compatibilidad nativa Xbox/Switch 2.** Ninguna operación ha conectado o escrito en el mando físico.

## Reproducción

```bash
python -m unittest tests.test_bruce_secondary_late_writers_phase44 tests.test_bruce_secondary_override_phase44 -v
python -m tools.audit_bruce_secondary_late_writers_phase44 local/bruce_pvt_a_prod_signed.bin --out local/phase44-writers.json
python -m tools.audit_bruce_secondary_override_phase44 local/bruce_pvt_a_prod_signed.bin --out local/phase44-override.json
```

La CI comprueba la identidad SHA-256 exacta `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3` del archivo OEM de actualización; luego destruye las copias temporales. [PR #46](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/46).
