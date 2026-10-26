# Fase 41 — Censo del callback secundario de clase 10 (Bruce firmado)

**26/10/2026 · PR #43 · Solo investigación offline sobre la imagen OEM original de actualización.**

## Resultado contrastado en GitHub Actions

La fase 40 identificó el callback de clase 10 firmado `0x600613FC`, que para códigos de solicitud superiores a `0x7F` lee un segundo puntero de función en **`0x20009EF8`**, su contexto en **`0x20009EFC`** y, si pasa un filtro, ejecuta `BLX R3`. **No sabemos si la ruta recibe solicitudes EP0 reales o quién instala ese segundo callback.**

El auditor `tools/audit_bruce_secondary_registry.py` exige la imagen OEM Bruce exacta (1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). Analiza Thumb XIP e ITCM reubicado y, de manera adicional, comienza expresamente en la entrada del callback firmada para evitar perder la alineación al desensamblar datos intercalados. El barrido usa propagación limitada de constantes; **no construye un CFG interprocedimental**.

| Medida | Resultado |
|---|---:|
| Instrucciones decodificadas linealmente, incluido solapamiento de la ventana de referencia | 180.127 |
| Lecturas/escrituras con dirección objetivo resuelta en este modelo | **1 lectura, 0 escrituras** |
| Lectura verificada | `0x6006140A: LDR R3,[R0,R3]` → `0x20009EF8` |
| Literales alineados que contienen exactamente `0x20009EF8/FC` | **0 / 0** |
| Referencias de palabra alineada a la base global `0x200064C0` | 58 (datos, no necesariamente instrucciones) |
| Referencias alineadas a la base de objeto `0x20009E00` | 3 |
| Referencias PC-relativas identificadas a ambas bases | 4 |
| Candidatos a `STR` con desplazamientos `+0xF8/+0xFC/+0x3A38/+0x3A3C` | **24** |

La dirección `0x20009EF8` está fuera de la **copia concreta de datos inicializados** conocida `0x20002740..0x20003FD8`. Esto **no** determina el valor real al arrancar, ni descarta que otra fase de inicialización escriba allí.

### Clasificación reproducible de las 24 escrituras candidatas

- **12** usan `SP` como base: son accesos con forma de desplazamiento coincidente respecto de pila, no una escritura acreditada en el registro secundario.
- **3** tienen dirección estática resuelta a **`0x20026160`**, diferente de `0x20009EF8/FC`.
- **9** usan bases de registro dinámicas/no resueltas en el tramo examinado y requieren estudio posterior.

Nueve candidatos no resueltos: `0x60058846`, `0x600A4FF2`, `0x600A54F4`, `0x600D574E`, `0x600DDB84`, `0x600EBD86`, `0x600F1C60`, `0x600F4E44`, `0x600FF9EC`.

Que un `STR` use el desplazamiento `+0xF8` **no prueba que su base sea `0x20009E00`**. La mayoría de bases se derivan de estructuras o marcos de función todavía no asociados al objeto de clase 10. Las ventanas descodificadas linealmente también pueden contener datos interpretados como instrucciones.

## Puerta de decisión siguiente

1. Para los nueve sitios, verificar primero los límites de función, llamadas y base real de objeto; descartar falsos positivos de desensamblado.
2. Seguir la procedencia de `R3/R4/R1` entre funciones; conectar con `0x20009E00` solo si la cadena de alias queda probada por instrucciones originales.
3. Si aparece un escritor de `0x20009EF8/FC`, verificar **origen del valor** y si una entrada externa lo controla. Una rutina de inicialización OEM con puntero firmado no sería por sí misma un bypass.
4. Diferenciar selección de clase 10/EP0 real, control externo, ejecución no firmada y recuperación. No tocar el único mando sin ruta recuperable.

**Decisión provisional:** se ha eliminado la hipótesis de un escritor directo con base constante detectable en el barrido acotado; **no** se ha demostrado que el segundo registro sea inmutable ni que pueda manipularse por USB. Sigue sin haber firmware propio, evasión de HAB CLOSED o soporte Xbox/Switch 2.

## Reproducción

```bash
python -m unittest tests.test_bruce_secondary_registry -v
python -m tools.audit_bruce_secondary_registry local/bruce_pvt_a_prod_signed.bin --out local/phase41.json
```

La ejecución CI obtiene temporalmente la imagen OEM pública, comprueba su SHA-256, ejecuta el auditor y elimina los ficheros temporales. **No hay peticiones al dispositivo ni escrituras de flash.** Los valores en esta nota proceden de la [ejecución verificable de GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40298495926). La imagen de actualización **no** equivale a un volcado byte a byte del firmware instalado.
