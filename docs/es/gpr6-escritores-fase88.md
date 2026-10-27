# Fase 88 — ¿Quién escribe el bit 3 de GPR6 que activa la actualización?

**27 de octubre de 2026.** Continuación de la [fase 87](bootloader-update-trigger-phase87.md). Investigación completamente **offline**. No conecta el mando, no envía comandos USB, no cambia RAM, flash ni fusibles.

## Respuesta obtenida hasta ahora

La fase 87 fijó que el bootloader A (build 169429) lee y borra el registro de estado **SRC_GPR6 en `0x400F8038`**, y solo entra en la actualización del bootloader si el valor anterior contenía el **bit 3 (`0x08`)**. Los parámetros que entrega al coordinador son constantes y objetos internos del firmware firmado. Seguía faltando el **productor de ese bit**.

Esta fase compara dos fuentes sin confundirlas:

1. El archivo público de **Bruce firmado original**, identificado por SHA-256 **`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`**. Se exige identidad del binario **antes** de analizar su contenido.
2. El conjunto **seleccionado** de instrucciones previamente extraídas del bootloader A y almacenadas en [evidence/bootloader-analysis.json](../../evidence/bootloader-analysis.json), con SHA-256 de procedencia **`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`**. El archivo privado completo **no estaba disponible** para repetir su hash en esta sesión.

## Hallazgos originales en Bruce

El [censo SHA-pinned](../../tools/audit_gpr6_provenance_phase88.py) encuentra **seis** palabras de 32 bits con `0x400F8000` (base del bloque SRC) en el intervalo anterior al CSF:

| Offset de archivo Bruce | Lecturas literales Thumb candidatas |
|---|---:|
| `0x1F160` | 5 |
| `0x1F188` | 3 |
| `0x204CC` | 1 |
| `0x38ABC` | 1 |
| `0xFD454` | 1 |
| `0xFD4AC` | 1 |

No aparece ninguna palabra literal directa con `0x400F8038` en esta región. **Esto no excluye que el código calcule la dirección sumando `0x38` a la base**. De hecho, la siguiente rutina original hace precisamente eso.

### Escritor de GPR6 identificado: no pone el bit de actualización

La secuencia **original firmada**, anclada a bytes exactos `237a012b264b0cbf052206229a63`, contiene:

```asm
0x60078A1C  LDRB  R3, [R4, #8]
0x60078A1E  CMP   R3, #1
0x60078A20  LDR   R3, [PC, #0x98]  ; literal 0x60078ABC = 0x400F8000
0x60078A22  ITE   EQ
0x60078A24  MOVEQ R2, #5
0x60078A26  MOVNE R2, #6
0x60078A28  STR   R2, [R3, #0x38]  ; escribe 5 ó 6 en 0x400F8038
```

**Hallazgo comprobado:** la instrucción `0x60078A28` escribe un valor **5 o 6** en GPR6 si se ejecuta la ruta original. Los dos valores tienen `0x08` a cero. Por ello **esta escritura no prepara la petición de actualización del bootloader A**.

Aún no está demostrada la procedencia del objeto apuntado por R4, qué evento alcanza este fragmento ni que su ejecución sea observable en el mando físico. Los otros literales son referencias candidatas y **no se declaran escritores** sin reconstrucción independiente de la ruta de instrucciones.

## Qué sabemos del bootloader A

Dentro de las **903 instrucciones originales seleccionadas** de [evidence/bootloader-analysis.json](../../evidence/bootloader-analysis.json), el análisis vuelve a comprobar estos accesos a GPR6:

| Sitio | Acción | Bit 3 |
|---|---|---|
| `0x60802866` | Leer estado GPR6 | No escribe |
| `0x6080286A` | Borrar GPR6 con cero | **0** |
| `0x60801F14` | Escribir estado por fallo de validación de aplicación: `0x10` o `0x20` | **0** |

Estas son **las únicas dos formas `STR [...,#0x38]`** del conjunto *seleccionado* cuya base se ha anclado a GPR6. **No son un censo completo del bootloader ni prueba de que no exista un escritor `0x08` en otra función, aplicación, cargador o rutina RAM.**

## Decisión

**GO** para una siguiente auditoría offline de *escritores indirectos y direcciones calculadas*, o un análisis del origen del evento de Bruce cuando aparezcan evidencias originales adecuadas. **NO-GO** para tratar `0x08` como controlable por USB, intentar activarlo manualmente o ejecutar una actualización en el mando único. La relación **USB → escritor GPR6 bit 3 → entrada bootloader** sigue sin probarse.

El código del bootloader intentaría autenticar el candidato mediante HAB y contiene la ventana de restauración no atómica descrita en [fase 86](bootloader-update-transaction-phase86.md). **No hay firmware propio ejecutado ni bypass HAB CLOSED**.

## Reproducibilidad

```sh
python -m unittest tests/test_gpr6_provenance_phase88.py -v
python -m tools.audit_gpr6_provenance_phase88 local/bruce_pvt_a_prod_signed.bin --out local/gpr6-phase88.json
```

El [workflow](../../.github/workflows/nxp-rom-advisories-phase81.yml) verifica SHA-256 de la muestra original de Bruce, ejecuta las pruebas sintéticas y borra los binarios temporales; no publica el archivo propietario. [Pruebas](../../tests/test_gpr6_provenance_phase88.py) · [Evidencia](../../evidence/gpr6-provenance-phase88.json) · [PR #97](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/97).
