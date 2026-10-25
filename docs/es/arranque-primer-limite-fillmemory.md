# FillMemory — orden de inicialización y primer límite de memoria (PR #30)

**25/10/2026 · Solo análisis offline.** Investigación sobre el cargador original firmado
`restricted_ivt_flashloader.bin`, de **100.672 bytes**, SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.
El archivo no se incorpora al repositorio. Ningún ensayo transmite comandos al
mando, modifica flash o eFuses ni escribe RAM física.

## A. ¿Se ejecuta la inicialización antes de aceptar FillMemory?

Se reconstruyó la inscripción de la rutina de inicialización
`0x20009904`, cuyo puntero Thumb `0x20009905` ocupa
`0x20016078`, es decir, el segundo campo de la tabla de proveedor
`0x20016074`. El global inicializado que referencia la tabla ocupa
`0x20208200` y proviene de la copia ROM/flash del cargador.
La imagen original **solo contiene una coincidencia alineada** del literal
`0x20009905` (`0x20016078`) y una de `0x20016074`
(en la copia inicial).

Se examinaron ventanas acotadas de funciones del cargador, incluyendo
`0x20002E5C`, `0x20002EB4`, `0x20003A98`,
`0x20003B7C` y `0x20009904`, y se buscaron llamadas
directas a `0x20009904` en un barrido Thumb de código. No se
encontró ninguna llamada directa en ese barrido **no exhaustivo**.
Esto es coherente con invocación indirecta a través de la tabla, pero
**no permite establecer que la llamada ocurra antes del despachador USB,
ni demostrar la secuencia completa de arranque**.

**Conclusión del apartado A:** está verificada la **inscripción**
y el código de la inicialización; **orden temporal y ejecución efectiva
pendientes de una traza dinámica o un grafo de llamadas indirectas
verdaderamente resuelto**. No se sustituye una prueba de ejecución por
una coincidencia de literales.

## B. ¿Qué pasa al superar las comparaciones con un extremo de 32 bits envuelto?

El código real de llenado `0x20002698` primero distingue longitud cero
y procesa una posible cabecera de alineación. Para direcciones iniciales
alineadas a cuatro bytes, en `0x200026C2` ejecuta
`CMP R2,#4`, seguido de `BLT` (**comparación con signo**) en
`0x200026C4`. Cuando la longitud de la hipótesis tiene el bit 31
establecido, la condición se cumple y salta al bucle de **escritura
byte a byte** de `0x200026FC`, que realiza `STRB` y decrementa el
contador hasta agotarlo. **No utiliza las ráfagas `STM` de 16 bytes**
para esos valores iniciales de longitud.

Las anclas `CMP/BLT/STRB/SUBS/BNE` están verificadas con Capstone
contra la imagen exacta. El modelo `tools/audit_fillmemory_first_boundary.py`
solo utiliza aritmética y un búfer descartable de hasta **64 bytes**.
No simula la CPU completa, interrupciones, el mapa físico del SoC ni
miles de millones de escrituras.

| Inicio examinado | Longitud teórica | Bytes dentro de la primera región declarada | Primera dirección fuera |
|---|---:|---:|---|
| `0x200159E0` (Execute) | 3.758.016.036 | 42.528 | `0x20020000` |
| `0x200159EC` (Call) | 3.758.016.024 | 42.516 | `0x20020000` |

El límite es el de la entrada RAM del **mapa del cargador**:
`0x20000000..0x2001FFFF`. `0x20020000` es la primera
dirección **fuera de esa entrada**, **no un fallo de bus medido**.
La CPU física puede tener alias, otras zonas mapeadas o efectos
no representados. La verificación del riesgo debe ser offline.

**El backend intentaría escribir una longitud enorme**, incluso después de
alcanzar regiones que contienen estructuras y tablas de su propio cargador.
Por tanto, que los filtros previos de 32 bits acepten un caso no
equivale a disponer de una instrucción aislada de escritura ni a poder
retornar con ejecución controlada.

## Estado de evidencias y decisión

| Cuestión | Resultado |
|---|---|
| Registro estático del inicializador | **Confirmado** |
| Inicializador ejecutado antes de atender comandos | **No demostrado** |
| Paso de filtros para algunos extremos envueltos | **Modelado sobre código verificado** |
| Ruta del bucle para las longitudes concretas | **Verificada: bytes por `BLT` con signo** |
| Primera salida de región RAM declarada | **Predicha offline en `0x20020000`** |
| Primer fallo de bus físico | **No se ha medido ni demostrado** |
| Escritura útil, retorno controlado, recuperación segura | **No demostrados** |
| Firmware propio / bypass HAB CLOSED | **No conseguido** |

El criterio racional es **no probar longitudes desbordadas físicamente
sobre el único mando**. La rama `FillMemory` sigue siendo una
observación de aritmética de límites, no una vía recuperable de
modificación de firmware. El siguiente trabajo, si se decide invertir
más en esta línea, debe probar **cómo y cuándo se invoca la tabla de
inicialización** con trazado de llamadas indirectas y un emulador
que aplique políticas de regiones, sin operaciones en el controlador.

## Reproducción

```sh
python -m unittest tests.test_fillmemory_first_boundary -v
python -m tools.audit_fillmemory_init_flow local/restricted_ivt_flashloader.bin --preview
python -m tools.audit_fillmemory_first_boundary local/restricted_ivt_flashloader.bin
```

Los comandos anteriores son exclusivamente de lectura local y exigen
el SHA-256 original. [Ejecución de GitHub Actions sobre el original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40237237957).
