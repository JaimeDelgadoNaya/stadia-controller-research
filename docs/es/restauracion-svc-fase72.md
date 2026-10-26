# Fase 72 — Restauración original de software hasta el retorno de excepción

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 71](normalizacion-contador-svc-fase71.md).

## Resultado principal

El wrapper SVC y el manejador **`0x6004CB40`** se ejecutan con sus instrucciones originales, usando la **misma máquina virtual conservada** al detener la fase 71 antes de SVC. El manejador carga la tarea seleccionada por el modelo, restaura R4–R11 y LR desde su frame, establece **PSP=`0x20020B28`** y limpia **BASEPRI a cero**.

La prueba se detiene antes de **`0x6004CB5A BX LR`**. **No se ejecutan SVC, la entrada real de excepción, el desapilado de hardware ni la entrada de tarea.** Acceder manualmente al manejador no equivale a que NVIC haya entregado una excepción.

## Estado conservado y entrada explícita

La fase 71 prepara la máquina virtual usando el constructor y registro originales de las fases anteriores y el perfil de readback de prioridad `0xF0`. Su estado previo a SVC conserva contador cero, BASEPRI `0x50` y MSP `0x2002B828`.

Una opción interna devuelve esa máquina sin reiniciar CPU ni memoria; se eliminan únicamente los hooks de parada de la fase anterior. La salida CLI por defecto de fase 71 conserva la misma evidencia.

La nueva etapa lee el vector SVC desde el VTOR **virtual** ya configurado. El valor `0x6004063D` conduce al wrapper que carga `0x6004CB41` desde el literal `0x60040744`. Se inicia manualmente ese wrapper, **saltándose el mecanismo de entrada de excepción** y sin apilado automático de MSP.

## Instrucciones originales y valores observados

El manejador lee el literal `0x20027410`, usado como puntero de tarea actual, y obtiene la estructura **`0x20020278`** y su frame **`0x20020B04`**. Es la tarea elegida en el modelo vacío de planificador; no se ha observado la tarea realmente seleccionada en el mando.

| Operación original | Resultado virtual |
|---|---|
| LDM.W de R4–R11 y LR en `0x6004CB46` | Coinciden con las palabras del frame preparado |
| MSR PSP en `0x6004CB4A` | **`0x20020B28`**, tras consumir nueve palabras |
| LR restaurado | **`0xFFFFFFFD`** |
| MSR BASEPRI en `0x6004CB56` | **0**, antes `0x50` |
| MSP durante este fragmento de software | Permanece `0x2002B828` |
| Última instrucción alcanzada | `0x6004CB5A BX LR`, **no ejecutada** |

Las palabras R4–R11 provienen del buffer virtual preparado, incluido su patrón de relleno; no son registros medidos del dispositivo ni un contexto de usuario real.

## Frame de hardware todavía pendiente

En la parada, el R0 actual de la CPU virtual vale **0**, utilizado por la limpieza de BASEPRI. En cambio, el R0 previsto para la tarea sigue en el frame apuntado por PSP:

| Palabra pendiente | Valor |
|---|---|
| R0 en `[PSP]` | **`0x2002014C`**, objeto Work Queue |
| PC en `[PSP+0x18]` | **`0x60101760`** |
| Estado en `[PSP+0x1C]` | `0x01000000` |

Estos valores aún **no** se han cargado como estado de CPU de la tarea. El retorno de excepción tendría que consumir ese frame; la prueba no lo simula ni ejecuta el BX LR. Por tanto, limpiar la máscara y preparar PSP no demuestra ejecución de trabajo.

## Reproducción y validación

```powershell
python -m tools.audit_svc_restore_phase72 local/bruce.bin --out local/phase72.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_svc_restore_phase72 -v
```

Requiere `requirements-emulation.txt` y la imagen exacta del [archivo OEM](https://github.com/StadiaMemories/firmware), obtenida por separado. Se verifica SHA, vector, literal de tarea, instrucciones y codificación exacta `0x4770` del BX LR. Las pruebas negativas alteran vector, carga múltiple y retorno. **762 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce la evidencia completa y la salida anterior de fase 71.

## Límites y continuación

La restauración de software ya no es solo estática: se ejecuta el código original y se comprueban sus registros. Sigue pendiente el **retorno de excepción y la ejecución de `0x60101760`**. Permanecen los modelos de readback, registros de sistema/temporizador, constructor y sincronización, y no se ha ejecutado el arranque completo del scheduler.

No se han enviado comandos al mando ni modificado firmware/eFuses. La activación física de clase 10, ejecución propia y elusión HAB siguen sin demostrarse.

[Evidencia](../../evidence/usb-svc-restore-phase72.json) · [Auditor](../../tools/audit_svc_restore_phase72.py)
