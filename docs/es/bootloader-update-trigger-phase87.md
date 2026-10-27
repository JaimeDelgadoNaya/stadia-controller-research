# Fase 87 — Procedencia del disparador de actualización del bootloader A (GPR6)

**27 de octubre de 2026.** Continuación de la [fase 86](bootloader-update-transaction-phase86.md). Auditoría **offline** del conjunto seleccionado de instrucciones extraídas previamente del bootloader A, build **169429**, SHA-256 registrado `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. El binario completo privado **no está disponible para un nuevo hash en esta fase**; la herramienta comprueba los bytes y destinos de instrucciones publicadas en [bootloader-analysis.json](../../evidence/bootloader-analysis.json), no la imagen física instalada.

## Nuevo hallazgo: disparador interno, no petición USB identificada

En el fragmento original firmado hay una rutina que **lee y borra el registro `0x400F8038`**, documentado previamente como **GPR6**. Guarda el valor anterior en `r4`, lo limita a ocho bits con `UXTB` y comprueba el **bit 3, máscara `0x08`**. Si el bit está a cero salta más allá del bloque de actualización; si está a uno prepara argumentos fijos y llama a `0x60801ED0`, que construye el contexto y llama al coordinador `0x60801DD4`.

Fragmentos de Thumb previamente extraído; los bytes, direcciones y ramas se comprueban en el [auditor de fase 87](../../tools/audit_bootloader_update_trigger_phase87.py):

```asm
0x60802860  LDR  R3, [PC, #0xA4]   ; literal = 0x400F8000
0x60802862  MOVS R2, #0
0x60802866  LDR  R4, [R3, #0x38]  ; instantánea de GPR6
0x6080286A  STR  R2, [R3, #0x38]  ; borra GPR6
0x6080286C  UXTB R4, R4
...
0x608028B0  LSLS R3, R4, #0x1C   ; signo = bit 3 original
0x608028B2  BPL  0x608028CE     ; salta el bloque si bit 3 = 0
...
0x608028C6  BL   0x60801ED0
```

**NO equivale a demostrar que el host USB pueda escribir ese bit.** Se desconoce qué rutina produce `GPR6 & 0x08`, si el estado sobrevive a los reinicios y si el mando real ha ejecutado esta rama. En los intervalos originales disponibles se observa además otro escritor, `0x60801F14`, que guarda `0x10` o `0x20` al detectar fallos de validación de aplicación; **ninguno incluye el bit 3**. Esto **no es un censo completo de escritores**.

## Los parámetros que llegan al coordinador

| Parámetro en la llamada a `0x60801ED0` | Procedencia dentro de las instrucciones originales |
|---|---|
| `r0 = 0x200095A8` | Literal `0x200090D8` más `0x4D0`, objeto de almacenamiento |
| `r1 = 0x6080285D` | Literal de callback **OEM** Thumb; remite al comprobador de alimentación/entrada |
| `r2 = 0x200090D8` | Literal de contexto interno para el callback |

Los bytes `0x608028B4–0x608028C6` confirman las cargas, escrituras temporales a pila, `LDM` y llamada directa. El wrapper `0x60801ED0` traslada esos valores a `0x60801CC8`, que busca el descriptor **`0x12`**, instala callback/contexto en el objeto y llama después a `0x60801DD4`. La [fase 86](bootloader-update-transaction-phase86.md) ya acreditó que ese coordinador contiene la prevalidación estructural, intento de escritura IVT, autenticación HAB posterior y recuperación condicionada.

**Consecuencia:** en esta secuencia, ni la dirección del callback ni el objeto de almacenamiento son valores recibidos directamente de un paquete USB. Son parámetros OEM. La procedencia del *bit de activación* continúa abierta.

## Reproducibilidad y límites

- El [auditor](../../tools/audit_bootloader_update_trigger_phase87.py) exige **31 instrucciones originales ancladas** y que pase el auditor de transacción de fase 86.
- El [test](../../tests/test_bootloader_update_trigger_phase87.py) comprueba los casos `0x08/0x18/0x28` frente a `0x10/0x20`, 256 valores posibles del byte bajo, y rechazo ante mutaciones de opcodes, literales o destinos.
- La CI ejecuta el nuevo test y verifica un informe JSON de solo metadatos. **No se lee ni escribe el GPR6 físico**.

**GO condicionado:** investigar el origen del escritor de GPR6 bit 3 dentro de una imagen original completa y confirmar los estados de reinicio sin cambiar firmware. **NO-GO** para activar manualmente bits, enviar comandos de actualización, programar IVT, modificar eFuses o probar cortes de alimentación en el único mando.

La versión HAB de ROM sigue desconocida; **no existe ejecución de firmware propio ni bypass HAB CLOSED demostrado**.

[Resultado saneado](../../evidence/bootloader-update-trigger-phase87.json) · [PR de la fase 87](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/96).
