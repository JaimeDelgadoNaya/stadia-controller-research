# Fase 71 — Normalización del contador y límite anterior a SVC

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 70](registro-planificador-fase70.md).

## Resultado principal

Se ha localizado la normalización del contador crítico **`0x20003D68`**: la rutina de arranque **`0x600CC5AC`** ejecuta **`0x600CC624 STR R5,[R4]`** con valor cero. La ruta solo alcanza esa escritura si supera antes una comprobación de los bits de prioridad disponibles.

La prueba ejecuta las instrucciones originales con modelos explícitos de lectura de prioridad. Con máscara virtual **`0xF0`**, normaliza el contador y llega a **`0x600CC536 SVC #0`**, donde se detiene **antes de ejecutar SVC**. No se inicia una tarea ni una conmutación de contexto.

## Qué estado se conserva y qué se modela

Se parte de la RAM construida mediante el registro original de fase 70, conservando el sentinela OEM `0xAAAAAAAA`. La máscara virtual `BASEPRI=0x50` observada al terminar ese registro se establece como entrada explícita de esta nueva etapa.

La entrada directa en `0x600CC5AC` es un fixture: **no se ejecuta todo el arranque de alto nivel del planificador**. La página `0xE000E000` es memoria virtual. El VTOR virtual se fija a la base OEM `0x60040000`, sin afirmar que sea el VTOR instalado en el mando.

La rutina prueba el byte **`0xE000E400`** escribiendo `0xFF` y leyendo su valor. El modelo devuelve `valor & máscara` en cada lectura de ese byte. Esto representa únicamente una hipótesis de readback, **no una medición de los bits físicos implementados** ni una emulación completa de NVIC.

| Máscara sintética de readback | Resultado original | Contador al detenerse | BASEPRI virtual |
|---|---|---|---|
| `0xFF` | Llamada de aserción antes de normalizar | `0xAAAAAAAA` | `0x50` |
| **`0xF0`** | Se detiene antes de SVC | **0** | **`0x50`** |
| `0xE0` | Llamada de aserción antes de normalizar | `0xAAAAAAAA` | `0x50` |

No se ejecuta la implementación de aserción: se detiene en su entrada `0x601016A2`. Tampoco se afirma que todos esos perfiles sean posibles en el hardware objetivo. El código firmado es compatible con el modelo probado `0xF0` en esta ruta concreta.

## Configuración previa a la entrega de control

En el caso aceptado se ejecutan los helpers originales `0x600CC578`, `0x600CC540` y `0x600CC518`. La rutina de temporizador usa la palabra de reloj del snapshot OEM en **`0x20003020`**, calcula `reloj/1000 - 1` y escribe el resultado en memoria virtual. Esa palabra no constituye una medición del reloj físico actual.

`0x600CC518` lee el VTOR virtual y la primera palabra de la tabla OEM, y carga **MSP=`0x2002B828`**. También ejecuta las instrucciones originales de CONTROL/máscaras y barreras antes de SVC. No se reproducen efectos reales de reloj, temporizador, interrupciones ni excepción.

**Normalizar el contador no ha limpiado todavía BASEPRI en este punto.** El límite observado es contador 0 y BASEPRI `0x50`, justo antes de SVC; no debe presentarse como una entrega de control ya completada.

## Manejador posterior identificado estáticamente

La palabra SVC de la tabla OEM es **`0x6004063D`**. Su wrapper carga el literal de `0x60040744`, cuyo destino Thumb es **`0x6004CB41`**.

El código original de ese manejador carga el estado de tarea, restaura registros y PSP, y contiene **`0x6004CB56 MSR BASEPRI,R0`**, precedida por `R0=0`, antes de **`0x6004CB5A BX LR`**. Estas instrucciones se verifican estáticamente en esta fase; **el manejador no se ejecuta**. La excepción real y su retorno son la siguiente frontera.

## Reproducción y validación

```powershell
python -m tools.audit_port_start_phase71 local/bruce.bin --out local/phase71.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_port_start_phase71 -v
```

Requiere `requirements-emulation.txt` y el archivo exacto del [archivo OEM](https://github.com/StadiaMemories/firmware), obtenido por separado. Se verifica SHA, instrucciones, literales, contador, aritmética del temporizador y límite SVC. Las pruebas negativas alteran la escritura de contador, SVC y limpieza del manejador. **758 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce y compara la evidencia completa.

Persisten los modelos de constructor/sincronización anteriores, el salto entre etapas y la ausencia de un scheduler físico activo. No se han enviado comandos al mando ni modificado firmware/eFuses; no se demuestra activación física de clase 10, ejecución propia o elusión HAB.

[Evidencia](../../evidence/usb-port-start-phase71.json) · [Auditor](../../tools/audit_port_start_phase71.py)
