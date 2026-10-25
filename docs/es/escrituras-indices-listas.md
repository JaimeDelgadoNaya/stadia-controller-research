# Fase 29 — Procedencia y límites del índice `+0x2C`

**Muestra privada:** Stadia bootloader A, build 169429, 131.072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Análisis estático **offline**; sin conectar el mando, enviar USB ni escribir flash/eFuses.

## 1. Cinco escrituras verificadas al índice en las funciones seleccionadas

El campo `objeto+0x2C`, usado en la fase 28 para seleccionar una lista
indexada, se escribe en varias rutas. En el intervalo de código
`0x60811400..0x60812200` (final exclusivo), un barrido **específico**
de codificaciones Thumb de 16 bits `STR Rt,[Rn,#0x2C]` encuentra estas
cinco coincidencias, que también se han comprobado en el desensamblado:

| Instrucción | Fuente de valor | Efecto y condición |
|---|---|---|
| `0x608115A0` | Parámetro de constructor en `R6` | Se limita sin signo a **15** antes de escribir |
| `0x60811F90` | `[objeto_referencia+0x2C]` | Copia el índice de otro objeto durante una transición |
| `0x60811FB2` | `[objeto_referencia+0x2C]` | Copia el mismo campo en una rama alternativa |
| `0x60812056` | `[objeto+0x50]` | Restaura el índice desde un campo propio |
| `0x608120D6` | Selección `R5` | Escribe el **máximo sin signo** del argumento y el campo `+0x50` en el tramo analizado |

Los valores copiados desde otro objeto proceden de una dirección guardada
en el puntero global `0x2000A7EC`. La dirección y contenido del
**objeto referenciado en ejecución** no se han medido.

Estas cinco escrituras **no son un inventario exhaustivo**: fuera de la
ventana y del formato de instrucción pueden existir más accesos,
incluidos alias, escrituras de 32 bits de otra clase, DMA u otros módulos.

## 2. Un límite superior demostrado en la inicialización

La secuencia inicial en `0x60811590..0x608115A2` es:

```asm
0x60811590  LDR     R6, [SP,#0x20]
0x60811596  CMP     R6, #0x0F
0x6081159C  IT      HS
0x6081159E  MOVHS   R6, #0x0F
0x608115A0  STR     R6, [R4,#0x2C]
0x608115A2  STRD    R6,R5, [R4,#0x50]
```

La comparación `HS` es **sin signo**. Para cualquier entrada inicial
de 32 bits sin signo, el índice escrito resulta `min(entrada,15)`
y está en el intervalo **0–15**. El constructor guarda además el mismo
`R6` en `objeto+0x50` mediante `STRD` (junto al otro campo).
Este hecho verifica el **estado inicial de este constructor**, no que
todos los índices del firmware permanezcan limitados a 15.

## 3. Cambios posteriores y comprobaciones locales

En `0x60811F52..0x60811F5C` se compara el índice del objeto actual
con el del objeto de referencia y existe un salto condicionado
`BHS`. Por tanto, el camino hacia `0x60811F90` tiene
condiciones de flujo previas; **no** equivale a una escritura sin
condiciones. En otra rama, `0x60811FB2` copia igualmente el
índice del objeto de referencia.

En `0x60812050..0x60812056`, se toma el valor
`[objeto+0x50]`. No hemos demostrado que dicho campo mantenga
siempre su valor inicial.

En `0x6081208E`, `R5` recibe un argumento del llamador.
Después, `0x608120A6` obtiene `R3=[objeto+0x50]`;
`CMP R5,R3` seguido de `IT LO; MOVLO R5,R3`
selecciona localmente **`max` sin signo**, que llega al
`STR` de `0x608120D6`, condicionado también por el camino
de control hasta él. **No aparece en ese tramo un nuevo límite
superior de 15 para los dos operandos.** Este hecho no significa
que el llamador carezca de validaciones.

## 4. Qué implica para las listas indexadas

La fase 28 identificó las cabeceras
`0x2000A7F8 + 20×índice`. El índice inicial de los objetos
construidos por la ruta examinada cae en 0–15, pero:

- Todavía no se ha demostrado el **número real de cabeceras asignadas**.
- Es necesario seguir la procedencia y las restricciones del argumento
  de `0x6081208C`, del campo `objeto+0x50` y del objeto
  accesible mediante `0x2000A7EC`.
- Las otras formas de escritura y los caminos desde USB continúan
  sin estar completamente estudiados.

**No hemos demostrado un índice fuera de límites, corrupción de memoria,
control externo del índice, modificación de callbacks ni una vía de
ejecución de firmware personalizado. HAB CLOSED sigue sin elusión.**

## 5. Reproducción

```powershell
py tools/audit_bucket_index_writers.py local/bootloader-a.bin --out local/phase29.json
py -m unittest discover -s tests -v
```

El script exige el SHA-256 completo, verifica cuatro huellas de
regiones, instrucciones Thumb concretas y la ubicación de las cinco
escrituras dentro de la ventana indicada. GitHub Actions usa
**únicamente imágenes sintéticas**; nunca incorpora el firmware
propietario.

**Fase 30 propuesta:** seguir la inicialización y posibles escrituras
sobre `objeto+0x50` y reconstruir de dónde procede el argumento
que selecciona el máximo, buscando restricciones efectivas antes
de formular hipótesis de vulnerabilidades.
