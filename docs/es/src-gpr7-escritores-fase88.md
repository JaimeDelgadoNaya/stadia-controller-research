# Fase 88 — Escritores de SRC_GPR7: corrección del mapa NXP y procedencia del bit 3

**27 de octubre de 2026. Solo lectura y sin mando conectado.** Continuación de la [fase 87](bootloader-update-trigger-phase87.md).

## Corrección necesaria

El [Manual de referencia NXP i.MX RT1060, Rev. 3, capítulo 21, tabla SRC y §21.6.10–11](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf) identifica:

| Registro | Dirección exacta | Observación |
|---|---|---|
| **SRC_GPR6** | `0x400F8034` | Reservado al uso de ROM |
| **SRC_GPR7** | `0x400F8038` | Reservado al uso de ROM; valor de reset documentado 0 |

**La fase 87 denominó erróneamente GPR6 a `0x400F8038`.** Su dirección, opcodes y comprobación del bit 3 eran correctos; el nombre correcto del registro es **GPR7**. Se ha corregido la PR 96, código, tests, documentos y evidencia. El manual indica que ambos registros los usa la ROM y que el software de aplicación no debe apropiárselos. **Esto no demuestra que la ROM del Stadia escriba el bit `0x08` ni que una orden USB pueda afectarlo.**

## Qué evidencias tenemos del bootloader A

En el [registro seleccionado de instrucciones originales](../../evidence/bootloader-analysis.json) hay **28 funciones y 903 instrucciones**, extraídas previamente de un bootloader A cuyo SHA-256 quedó registrado. No está disponible el binario privado completo en esta sesión; la comprobación vuelve a validar opcodes/literales/callsites conocidos, **no recalcula el hash de toda su imagen**.

La [herramienta](../../tools/audit_src_gpr7_writers_phase88.py) recorre las funciones publicadas y atribuye a GPR7 solamente los `STR` que siguen en la misma función a una carga literal verificada de base `0x400F8000` en R3, con desplazamiento `+0x38`. Encuentra dos escrituras:

| Dirección de instrucción | Valor atribuido | Significado del camino local |
|---|---|---|
| `0x6080286A` | **0** | Borra GPR7 después de capturar el valor anterior |
| `0x60801F14` | **0x10 o 0x20** | Escribe un código de estado al fallar la validación de aplicación |

**Ninguna de estas escrituras establece el bit 3 (`0x08`)**. Su número **no prueba que no haya un tercer escritor**: el corpus cubre un conjunto seleccionado de instrucciones, no todo el bootloader. Quedan fuera los registros de origen dinámico, direcciones calculadas, instrucciones no incluidas y código de ROM.

En la fase 87 ya se comprobó la otra mitad de la lógica: en `0x608028B0`, el código firmado prueba ese bit del valor previo y, si está activo, **llama condicionalmente a** `0x60801ED0`. La función de actualización utiliza parámetros y callbacks OEM fijos; **se desconoce la procedencia del bit antes del arranque**.

## Segunda fuente: muestras OEM originales públicas

El auditor puede inspeccionar las versiones públicas **Bruce firmada** y **cargador RAM firmado**, siempre con SHA-256 original comprobado mediante [fase 81](../../tools/audit_nxp_rom_advisories_phase81.py). Busca las constantes little-endian `0x400F8000`, `0x400F8034` y `0x400F8038` a intervalos de dos bytes **antes de cada CSF**.

Los resultados son **palabras de datos candidatas**, no referencias confirmadas de instrucciones ni escrituras ejecutadas. No detectan combinaciones con `MOVW/MOVT`, sumas sobre registros, accesos por punteros dinámicos o código de BootROM. Un censo negativo no demuestra ausencia de escritores.

## Reproducción

```sh
python -m unittest tests/test_src_gpr7_writers_phase88.py -v
python -m tools.audit_src_gpr7_writers_phase88 --out local/src-gpr7-bootloader-phase88.json
python -m tools.audit_src_gpr7_writers_phase88 --public-image local/bruce_pvt_a_prod_signed.bin --sample bruce_prod --out local/src-gpr7-bruce.json
python -m tools.audit_src_gpr7_writers_phase88 --public-image local/restricted_ivt_flashloader.bin --sample restricted_ram_loader --out local/src-gpr7-loader.json
```

La [CI](../../.github/workflows/nxp-rom-advisories-phase81.yml) utiliza temporalmente las muestras OEM originales, exige sus SHA-256, ejecuta las pruebas sintéticas y borra los archivos. No accede al mando ni a sus fusibles, flash o registros.

## Decisión de investigación

**GO** solamente para buscar evidencia independiente del escritor del **bit 3 de SRC_GPR7**, de su persistencia real durante reinicios y de un eventual origen externo, sin asumir que esos hechos se han demostrado. **NO-GO** para modificar bits de GPR7, forzar saltos al actualizador o escribir IVT en el único mando, dado el riesgo de recuperación ya identificado.

Aún no hay ejecución de firmware propio, bypass HAB ni autenticación eludida. La versión exacta HAB ROM sigue desconocida.

[**Evidencia saneada fase 88**](../../evidence/src-gpr7-writers-phase88.json) · [PR fase 88](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/97).
