# Fase 69 — Preparación original de tarea y procedencia del handle

**26 de octubre de 2026.** Análisis offline de Bruce OEM con SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 68](constructor-workqueue-fase68.md).

## Resultado principal

Se ejecuta **`0x600CA1F8`** con las estructuras suministradas por el constructor OEM. Su retorno ya no se sustituye por un handle opaco: las instrucciones originales producen **`0x20020278`**, la estructura de estado preasignada de fase 68.

También se ejecutan la preparación original **`0x600CA0FC`**, la inicialización local **`0x601007B6`** y la construcción del frame **`0x600CC554`**. **No se ejecutan la entrada de la tarea ni su registro real en el planificador.** Ese registro, `0x600C9FD8`, conserva un stub sin efectos.

## Procedencia del handle

La ruta original utiliza los argumentos del wrapper `0x600CC178` y el puntero auxiliar creado por el constructor:

1. `0x600CA1F8` obtiene la estructura de estado y el buffer preasignados; los argumentos no nulos evitan las rutas de error de este caso.
2. `0x600CA242` escribe el buffer en `estado+0x30`.
3. La llamada original a `0x600CA0FC` prepara el estado y el frame, y **`0x600CA1A0 STR R4,[R7]`** escribe el puntero de estado en el parámetro de salida.
4. Tras el registro simulado, **`0x600CA264 LDR R0,[SP,#0x14]`** recupera ese valor preparado por el código original.
5. El wrapper original lo almacena en **`objeto+0x58 = 0x200201A4`**.

El resultado es **`0x20020278`**, no el valor opaco de fases anteriores. Esto verifica la procedencia en la ruta preasignada bajo el modelo; no acredita todas las variantes posibles de creación ni una tarea válida en hardware.

## Estado y frame preparados

| Campo virtual | Valor producido por código original |
|---|---|
| Handle/estructura de estado | **`0x20020278`** |
| Buffer en `estado+0x30` | `0x2002034C` |
| Tamaño original | `0x200` palabras |
| Puntero de frame almacenado en el estado | **`0x20020B04`** |
| Palabra `estado+0x2C` | 1 |
| PC preparado en `frame+0x3C` | **`0x60101760`** |
| R0 preparado en `frame+0x24` | **`0x2002014C`**, objeto Work Queue |
| Palabra de estado en `frame+0x40` | `0x01000000` |
| Palabra de retorno en `frame+0x20` | `0xFFFFFFFD` |

El cálculo del frame se ejecuta: buffer + tamaño en bytes − 4, alineación a 8 y reserva de `0x44` bytes. La evidencia verifica el resultado contra esa ecuación y los valores escritos. **Preparar un PC no equivale a saltar a él.** El auditor no ejecuta `0x60101760` ni una conmutación de contexto.

El relleno de memoria se modela como escritura acotada de bytes en SRAM virtual, incluyendo el patrón original `0xA5` del buffer. No se publican su contenido completo ni un snapshot de RAM.

## Continuidad posterior y modelos pendientes

La función de modo retorna usando el handle generado por estas instrucciones. La etapa de transición/driver de fases 66–68 vuelve a enlazar la instancia de clase 10 **`0x200040E0`**, con MMIO virtual 8. Mantiene las mismas limitaciones: join por etapas, helpers de registro/sincronización, otras clases no ejecutadas y parada anterior a la publicación final del modo.

**`0x600C9FD8` no se ejecuta:** su stub conserva R0 y no registra ni planifica tareas. Se hereda también el modelo de `0x6013D3D0` del constructor. No se demuestra que las funciones reales retornen siempre ni se reproducen concurrencia, eventos de trabajo o efectos de hardware.

## Reproducción

```powershell
python -m tools.audit_task_handle_phase69 local/bruce.bin --out local/phase69.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_task_handle_phase69 -v
```

Requiere `requirements-emulation.txt` y la imagen exacta del [archivo OEM](https://github.com/StadiaMemories/firmware), obtenida por separado. Se verifica SHA, semántica del retorno/almacenamiento y frame, y resultados completos. Las pruebas negativas alteran el store del handle, el store del PC y la carga de retorno. **750 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce la evidencia. Las opciones anteriores de fase 67 mantienen la misma salida por defecto.

## Siguiente frontera

El handle ya procede del código original y de una estructura OEM preasignada. Queda por resolver el **registro `0x600C9FD8` y sus dependencias de kernel**, y después la ejecución de la entrada preparada y su procesamiento de trabajo. El resultado actual no demuestra una tarea ejecutándose ni activación física de clase 10.

No se han enviado comandos al mando, modificado firmware/eFuses, ejecutado código propio en el dispositivo ni superado HAB CLOSED.

[Evidencia](../../evidence/usb-task-handle-phase69.json) · [Auditor](../../tools/audit_task_handle_phase69.py)
