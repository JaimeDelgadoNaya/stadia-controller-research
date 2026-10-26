# Fase 42 — Alias entre funciones y origen firmado del callback secundario Bruce

**26/10/2026 · PR #44 · Auditoría original offline, sin operaciones USB ni modificación del mando.**

## Descubrimiento: escritura inicial de puntero/contexto mediante base dinámica

El callback firmado de clase 10 `0x600613FC`, identificado en fase 40, lee el puntero en `0x20009EF8` y contexto en `0x20009EFC`, y compara el primero con el sentinela Thumb **`0x600D4F05`**. La función de referencia `0x600D4F04` ejecuta `MOV.W R0,#0; BX LR` y retorna cero.

Se ha localizado en el archivo OEM **original firmado** una secuencia que la fase 41 no identificaba porque **calcula la dirección por registro, no mediante un `STR` con dirección absoluta**:

| Instrucción original | Operación |
|---|---|
| `0x60073BF4: MOV R4,R0` | Conserva la base facilitada como primer argumento |
| `0x60073C0C: MOVS R5,#0` | Inicializa el valor cero |
| `0x60073CE6: LDR R1,[PC,#0x13C]` | Carga el puntero `0x600D4F05` desde literal firmado en `0x60073E24` |
| `0x60073CEA: MOVW R3,#0x3A38` | Calcula desplazamiento de callback |
| `0x60073CF2: ADDS R2,R4,R3` | Prepara dirección del callback |
| `0x60073CF4: STR R1,[R4,R3]` | Escribe el callback sentinela en `base+0x3A38` |
| `0x60073CFC: STR R5,[R2,#4]` | Escribe cero en `base+0x3A3C` |

**Si** `R0 = 0x200064C0` al entrar en `0x60073BF0`, estas direcciones son respectivamente **`0x20009EF8` y `0x20009EFC`**, exactamente la pareja leída por la clase 10.

**Límite crítico:** el censo lineal de llamadas `BL` XIP no encontró un llamador directo de `0x60073BF0`, y tampoco halló una palabra literal alineada con su puntero Thumb `0x60073BF1`. Por tanto, **no se ha acreditado quién le pasa el argumento, que esta rutina se ejecute en la placa ni que el valor real sea el sentinela**. Que ambas estructuras coincidan matemáticamente es evidencia condicional, no un desvío ejecutable o explotable.

Si se confirma el argumento y el arranque ejecuta esta rutina, el valor inicial sentinela provoca que el guard de `0x6006140C/0x6006140E` no invoque el callback secundario; esta inferencia se limita al estado de inicialización y no prueba la ausencia de sustituciones posteriores.

## Inspección de los nueve candidatos de la fase 41

Los nueve sitios están presentes en las instrucciones OEM originales. El auditor `tools/audit_bruce_secondary_alias_phase42.py` recupera ventanas Thumb con múltiples puntos de comienzo para no forzar falsas alineaciones a través de datos intercalados, y calcula solo la **procedencia dentro del bloque básico inspeccionado**.

| Sitio | Escritura | Procedencia verificada o límite |
|---|---|---|
| `0x60058846` | `STRB [R4+0xFC]` | R4 procede del parámetro R0 de constructor `0x600587FC`; se ha seguido **una llamada directa** |
| `0x600A4FF2` | `STR [R3+0xF8]` | R3 = `[R7+0x1C]`; objeto indirecto |
| `0x600A54F4` | `STR [R3+0xF8]` | R3 = `[R7+0x14]`; objeto indirecto |
| `0x600D574E` | `STR [R4+0xFC]` | R4 llega como argumento a la rutina candidata; sin raíz real identificada |
| `0x600DDB84` | `STR [R1+0xFC]` | Base externa al bloque local; depende de procedencia anterior |
| `0x600EBD86` | `STR [R4+0xF8]` | R4 no se resuelve en el bloque posterior a llamada |
| `0x600F1C60` | `STR [R3+0xF8]` | R3 = `[R7+0x14]`; objeto indirecto |
| `0x600F4E44` | `STRB [R3+0xF8]` | R3 = `[R7+4]`; objeto indirecto |
| `0x600FF9EC` | `STRB [R3+0xFC]` | R3 = `[R7+4]`; objeto indirecto |

La única llamada directa descubierta al constructor `0x600587FC` ocurre en `0x60058926`. El original contiene `LDR R4,[PC,#0x12C]` en `0x60058914`, que obtiene **`0x20015E74`** de la dirección literal `0x60058A44`; inmediatamente `MOV R0,R4` antes del `BL`. En esta llamada, `0x60058846` escribe en **`0x20015F70`**, no en las dos direcciones investigadas. **Descartado para esa llamada, no necesariamente para posibles llamadores indirectos.**

## Qué demuestra y qué no

**Demostrado en los bytes originales:** la secuencia del sentinela y el contexto nulo, diez anclas Thumb de inicialización, la lectura de la clase 10 ya acreditada en fase 40 y el argumento diferente de una llamada concreta al constructor secundario. La imagen OEM es una actualización firmada, **no una extracción completa hash-verificada del firmware instalado**.

**Pendiente:** vínculo del inicializador `0x60073BF0` a la ejecución de inicio, valor real de su R0, lista completa de escritores posteriores en `base+0x3A38/3A3C`, alias interprocedimentales de los sitios restantes y activación EP0/USB real. No está demostrado control desde el host, bypass HAB CLOSED, ejecución de firmware propio, recuperación segura ni compatibilidad con Xbox o Switch 2.

**Decisión:** esta fase encuentra un **inicializador firmado condicional** que explica el sentinela y aporta un descarte parcial de alias. El siguiente paso tiene que demostrar un **llamador real e identidad de base**, no repetir barridos indiscriminados de stores.

## Reproducción

```bash
python -m unittest tests.test_bruce_secondary_alias_phase42 tests.test_bruce_class10_secondary_init_phase42 -v
python -m tools.audit_bruce_secondary_alias_phase42 local/bruce_pvt_a_prod_signed.bin --out local/phase42-alias.json
python -m tools.audit_bruce_class10_secondary_init_phase42 local/bruce_pvt_a_prod_signed.bin --out local/phase42-init.json
```

En GitHub Actions se descarga temporalmente la misma imagen OEM firmada, se verifica el SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3` y se destruye el archivo tras el análisis. Ver la [auditoría en Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40301594977).
