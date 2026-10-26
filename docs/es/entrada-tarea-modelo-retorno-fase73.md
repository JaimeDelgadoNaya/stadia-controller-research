# Fase 73 — Retorno de excepción modelado y entrada original de tarea

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 72](restauracion-svc-fase72.md).

## Resultado principal

Tras una **representación explícita del retorno de excepción**, se ejecutan las instrucciones originales de la entrada **`0x60101760`** y su método de trabajo **`0x600EE142`**, hasta la primera llamada de cola en **`0x600EE152`**, antes de ejecutarla.

El retorno de excepción **no** se ha ejecutado mediante SVC/BX LR o NVIC: se cargan manualmente los registros previstos en el frame. Lo ejecutado a continuación es código OEM dentro de la máquina virtual. **No es una tarea ejecutándose en el mando físico.**

## Transformación modelada del frame

Se conserva la máquina de las fases 71–72: el manejador original ya dejó BASEPRI a cero y PSP=`0x20020B28`, antes de BX LR. El modelo solo admite el perfil observado: retorno `0xFFFFFFFD`, frame básico de ocho palabras, estado Thumb/hilo y alineación sin palabra adicional.

Las palabras R0–R3, R12, LR, PC y estado se leen del frame preparado por el código OEM y se cargan mediante las APIs del emulador. Se representa el consumo de 32 bytes y la selección de PSP para el hilo virtual. Se rechazan perfiles extendidos, tamaños distintos, alineación no modelada y estado de excepción.

| Dato del modelo | Valor |
|---|---|
| PSP antes del consumo | `0x20020B28` |
| PSP seleccionado para la tarea | **`0x20020B48`** |
| R0 cargado desde el frame | **`0x2002014C`**, objeto Work Queue |
| PC cargado desde el frame | **`0x60101760`** |
| MSP conservado | `0x2002B828` |

Esta transformación es **una hipótesis acotada de ejecución**, no una emulación arquitectónica completa de excepciones ni una comprobación del comportamiento físico. No se ejecuta la instrucción BX LR de fase 72.

## Instrucciones originales posteriores

La entrada original recibe R0=Work Queue, lee su vtable **`0x60115C34`** y el método de `vtable+8`, cuyo puntero Thumb es **`0x600EE143`**. El BLX original en `0x6010176A` entra en `0x600EE142`.

El método original prepara su frame y alcanza esta llamada:

| Parámetro observado antes del BL | Valor/función local |
|---|---|
| R0 | **`0x200201AC`**, control de cola leído de `WorkQueue+0xB0` |
| R1 | Buffer de salida en el stack virtual |
| R2 | **`0xFFFFFFFF`**, valor de espera preparado por el código |
| Destino del BL en `0x600EE152` | **`0x6013D268`** |

La prueba se detiene **antes** del BL. No se demuestra que la recepción tenga éxito, que bloquee, que se ejecute una planificación ni que haya trabajos en la cola. Tampoco se ejecutan las ramas posteriores que podrían invocar callbacks de elementos.

## Reproducción y validación

```powershell
python -m tools.audit_task_entry_phase73 local/bruce.bin --out local/phase73.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_task_entry_phase73 -v
```

Requiere `requirements-emulation.txt` y el archivo exacto del [archivo OEM](https://github.com/StadiaMemories/firmware), obtenido por separado. Se verifican SHA, entrada, acceso indirecto y llamada de cola. Hay pruebas de rechazo del modelo de frame y mutaciones de BLX, carga de control y primer BL. **767 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce la evidencia completa.

## Límite y continuación

Se ha enlazado el frame construido con la entrada OEM mediante un puente **modelado**, y ejecutado su despacho original hasta la cola. Quedan pendientes la rutina **`0x6013D268`**, las condiciones de recepción y los productores de elementos de trabajo. No existe todavía un enlace acreditado desde un paquete USB físico hasta esos elementos o sus callbacks.

Persisten los modelos previos de constructor, sincronización, registros de sistema/prioridad/temporizador y el arranque incompleto del scheduler. No se han enviado comandos al mando ni modificado firmware/eFuses. La activación física de clase 10, ejecución de código propio y elusión HAB siguen sin demostrarse.

[Evidencia](../../evidence/usb-task-entry-phase73.json) · [Auditor](../../tools/audit_task_entry_phase73.py)
