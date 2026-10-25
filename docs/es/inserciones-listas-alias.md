# Fase 27 — Inserción de nodos y búsquedas de reasignación de punteros

**Muestra:** bootloader A Stadia, build 169429, 131.072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Análisis offline del archivo original privado. Sin dispositivo USB, programación de flash o modificación de eFuses.

## Hallazgo 1 — Dos funciones de inserción de nodos

La fase 25 había identificado el desenlazador de listas `0x608109FE`. Ahora encontramos
las dos funciones complementarias:

| Función | Operación reconocible | Referencias verificadas |
|---|---|---|
| `0x608109B8` | Inserción de un nodo junto al principio de una lista doblemente enlazada | **9 `BL` directos** |
| `0x608109D0` | Inserción ordenada: compara el valor del nodo con los vecinos antes de enlazarlo | **4 `BL` directos** y **1 salto `B.W`** |

Las **14 transferencias estáticas** han sido decodificadas a partir de las instrucciones Thumb originales. Las cifras describen el inventario de llamadas directas verificadas, no una búsqueda exhaustiva de todas las posibles entradas indirectas.

La función `0x608109B8` toma `R0` como cabecera y `R1` como nodo. Recupera el primer enlace, establece `[nodo+4]` y `[nodo+8]`, actualiza ambos vecinos, escribe `[nodo+0x10]=cabecera` y **aumenta el contador `[cabecera]`**.

La función `0x608109D0` inspecciona el valor `[nodo]`, recorre la lista mediante una comparación `CMP/BHI`, enlaza el nodo en la posición seleccionada y también aumenta el contador. Se verifica el patrón de **inserción por clave**, pero no se atribuye una semántica de aplicación externa a esa clave.

## Hallazgo 2 — Listas indexadas distintas de las cabeceras de fase 26

Dos de las llamadas a inserción directa en `0x608109B8` calculan la cabecera
de destino con **base RAM `0x2000A7F8` y stride de 20 bytes**:

| Llamada | Operación previa | Dirección calculada |
|---|---|---|
| `0x60811A32` | `MLA R0,R12,R0,R3`, con `R12=0x14` y literal `R3=0x2000A7F8` | `0x2000A7F8 + 20 × índice` |
| `0x60811E0C` | `MLA R0,R0,R2,R3`, con `R0=0x14` y literal `R3=0x2000A7F8` | `0x2000A7F8 + 20 × índice` |

Los índices proceden de campos del controlador en sus respectivos caminos. **No se han verificado aquí los límites de esos índices ni los valores de la RAM en ejecución.**

La base `0x2000A7F8` es distinta de las dos cabeceras inicializadas en fase 26,
`0x20009114` y `0x20009128`. Por tanto, sería incorrecto atribuir
automáticamente todas las llamadas de inserción a aquellas dos listas.

## Hallazgo 3 — Reasignación de `global+0x560/+0x568`

Se ha repetido un censo muy específico en los bytes `0x60801000..0x60814F00`
(final exclusivo): codificaciones de `STR.W Rt,[Rn,#imm12]` Thumb-2, con
desplazamiento positivo.

| Campo RAM | Única coincidencia de esta codificación |
|---|---|
| `global+0x560 = 0x200090D8` | `0x6080BAEC` |
| `global+0x568 = 0x200090E0` | `0x6080BAF2` |

Ambas instrucciones pertenecen al constructor ya identificado en la
fase 26 y almacenan inicialmente `global+0x134 = 0x20008CAC`.

**La búsqueda no demuestra que estos punteros nunca cambien.** Quedan
fuera escrituras por otros desplazamientos respecto a un alias, modos
`STRD/STM`, direcciones calculadas, llamadas no resueltas, DMA
u otro firmware. Tampoco se ha reconstruido un grafo de alcanzabilidad desde USB.

## Reproducción sin riesgo físico

```powershell
py tools/audit_list_insertion_paths.py local/bootloader-a.bin --out local/phase27.json
py -m unittest discover -s tests -v
```

El auditor exige el SHA-256 íntegro del binario A, verifica cinco huellas de
código, instrucciones del enlazado/ordenación, los 14 destinos directos y las
direcciones literales del conjunto indexado. GitHub Actions usa únicamente
muestras sintéticas. El archivo original nunca se publica.

**Siguiente objetivo (fase 28):** clasificar la procedencia de los nodos
que llegan a estas inserciones y comprobar los rangos y validaciones de
los índices, sin inferir acceso USB externo. Continúan sin demostrarse
la modificación de callbacks, la ruta host→flash o el bypass de HAB CLOSED.
