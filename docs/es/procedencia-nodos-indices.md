# Fase 28 — Procedencia de nodos e índices de las listas indexadas

**Muestra privada:** bootloader A Stadia build 169429, 131.072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Análisis estático **offline**. No se ha conectado el mando, enviado comandos
USB ni programado memoria o eFuses.

## Hallazgo principal

Las dos llamadas seleccionadas a `0x608109B8` insertan un **subobjeto
embebido en un objeto mayor**. El índice de lista procede del campo
`+0x2C` de ese mismo objeto, no de un literal fijo.

| Campo | Ruta A | Ruta B |
|---|---|---|
| Llamada de inserción | `0x60811A32` | `0x60811E0C` |
| Objeto principal | `R6` obtenido de dos cargas desde punteros | `R4` obtenido de `[[R0+0xC]+0xC]` |
| Nodo que se inserta | `R6+4` (en `R8`) | `R4+4` (en `R5`) |
| Índice utilizado | `[R6+0x2C]` | `[R4+0x2C]` |
| Cálculo de cabecera | `0x60811A2E` | `0x60811E08` |

Ambas rutas calculan:

[
H = 0x2000A7F8 + 20\,i
]

La instrucción es `MLA` ARM Thumb. Este cálculo expresa un
**desplazamiento de 20 bytes por índice**; **no valida que el índice
corresponda a una cabecera de lista realmente asignada**.

## Cadena de procedencia de cada ruta

**Ruta A — `0x60811A32`:**
`R2=[R10]` → `R2=[R2+0xC]` → `R6=[R2+0xC]`.
`0x608119FE` calcula `R8=R6+4`. Después
`0x60811A14` carga `R0=[R6+0x2C]`,
`0x60811A2E` calcula la cabecera con `MLA`, y
`0x60811A2C` había preparado `R1=R8`.

**Ruta B — `0x60811E0C`:**
`0x60811DCA` carga `R3=[R0+0xC]` y
`0x60811DCC` obtiene `R4=[R3+0xC]`.
`0x60811DEC` calcula `R5=R4+4`;
`0x60811DF6` lee `R2=[R4+0x2C]`; por último,
`0x60811E08` calcula la cabecera y
`0x60811E04` coloca `R1=R5`.

**No conocemos las direcciones RAM de los objetos principales en
ejecución ni el valor numérico real de sus índices.** Tampoco hemos
demostrado que el host USB pueda modificarlos.

## Observación sobre validaciones

En la ruta A, tras la llamada de inserción en `0x60811A32`,
aparece `CMP R1,R2` en `0x60811A3C`, usando una recarga
del índice y un campo de otro objeto.

En la ruta B, tras insertar en `0x60811E0C`, se ejecuta
`CMP R2,R3` en `0x60811E18` con valores recargados.

**Las comparaciones posteriores no constituyen por sí mismas una
validación previa del índice empleado para calcular la cabecera.**
En los tramos inmediatos examinados no hemos identificado una
comprobación de límites específica antes de esas dos llamadas.
Esto **no demuestra** que no exista una validación anterior en el
llamador, una restricción del estado del objeto o una garantía de
construcción del índice en otra función. La ruta A también contiene
accesos a la tabla indexada antes de llegar a la inserción.

Por tanto, **no se ha demostrado un acceso fuera de límites, corrupción
de memoria ni una vulnerabilidad explotable**.

## Evidencia y límites

El auditor `tools/audit_bucket_node_provenance.py` verifica:

- SHA-256 completo de la copia local del bootloader.
- Cuatro regiones con fingerprints SHA-256.
- Bytes de las instrucciones `LDR`, `ADD`, `MOV`, `MLA`,
  `CMP`, literales y cuatro llamadas directas `BL`.
- Orden de las cargas de índices y de las comparaciones posteriores.

Las pruebas de GitHub Actions usan **únicamente imágenes sintéticas**,
no el firmware original.

```powershell
py tools/audit_bucket_node_provenance.py local/bootloader-a.bin --out local/phase28.json
py -m unittest discover -s tests -v
```

## Continuación propuesta — Fase 29

Revisar **cómo se asigna el campo `+0x2C` de los objetos** y si su
dominio de valores está definido por una estructura, contador o comprobación
que anteceda a estas rutas. Examinar también las llamadas que crean
o registran dichos objetos antes de concluir nada sobre índices inválidos.

No existe una ruta host→USB→escritor flash demostrada ni bypass HAB CLOSED.
