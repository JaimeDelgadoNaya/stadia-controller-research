# Fase 67 — Resolución de la llamada pendiente y sus condiciones de retorno

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 66](driver-usb-modo-previo-fase66.md).

## Resultado principal

La llamada **`0x6009267C`**, que antes se omitía entre etapas, se ejecuta ahora con sus instrucciones originales hasta su retorno o hasta una rama de error observada. Accede al objeto SRAM **`0x2002014C`** y utiliza la etiqueta OEM **«Work Queue Task»**, situada en `0x6012F592`.

La etiqueta y la forma del código apuntan a una operación de creación/registro de tarea; **no se ha ejecutado ni validado un scheduler real**. No es una lectura del objeto instalado ni una prueba de tarea en ejecución.

## Ruta y campos originales

`0x60060F28` escribe primero 1 en `owner+0x90` y luego llama a `0x6009267C` con argumento 1. Esta última consulta:

| Campo | Dirección SRAM | Comportamiento del código |
|---|---|---|
| Objeto de cola | `0x2002014C` | Base cargada desde literal OEM |
| Campo handle `+0x58` | `0x200201A4` | Si es no nulo, devuelve cero sin entrar en la ruta de creación |
| Estructura auxiliar `+0x5C` | `0x200201A8` | Consultada si el handle está vacío |

La ruta sin handle pasa por `0x6010177A` y **`0x600CC178`**. Allí, una estructura auxiliar nula devuelve **9**. Con estructura presente se lee su palabra `+0xD0`, se desplaza dos bits y se compara con `0x800`: el cálculo es **`(word << 2) mod 2^32`**, no una regla universal sobre el tamaño original. Si el resultado queda por debajo, devuelve **3**. Para el caso probado `word=0x200`, se llama a **`0x600CA1F8`** y su retorno se almacena en el campo handle.

Esa última rutina es un **stub con un retorno opaco no nulo** en la prueba. No se han ejecutado asignación de memoria, creación de tarea ni sus efectos reales. Los dos hooks de sincronización del wrapper también conservan modelos sin efectos.

## Cuatro experimentos con código original

| Handle virtual inicial | Estructura auxiliar | Palabra `+0xD0` | Estado del helper | Resultado de la función de modo |
|---|---|---|---:|---|
| No nulo | No necesaria | — | **0** | Retorna al llamador original `0x600747B6` |
| Cero | Ausente | — | **9** | Rama de error en `0x60060F3E`, antes de logging |
| Cero | Presente | `0x1FF` → `0x7FC` | **3** | Misma rama de error |
| Cero | Presente | `0x200` → `0x800` | **0**, con creación simulada | Retorna al llamador; handle contiene el retorno opaco |

**En los cuatro casos el campo de modo ya vale 1**, porque su escritura precede a la llamada. Por tanto, observar esa escritura por sí sola no demuestra que la función de activación haya terminado correctamente.

En el primer caso, el camino rápido no ejecuta la rutina de creación ni los hooks de sincronización del wrapper. El código solo comprueba que el campo no sea cero: **no valida que el valor corresponda a una tarea válida o en ejecución**. Los campos son vectores de prueba virtuales, no estados medidos en el mando.

## Unión posterior al retorno completo

La prueba comienza en el fragmento de llamador `0x60074772`, conserva los modelos de cuatro helpers de registro y los argumentos sintéticos de fase 66. Ejecuta el cálculo de owner, la llamada de modo, la llamada antes pendiente, sus retornos y la reanudación original en `0x600747B6`.

Solo tras ese retorno normal, el experimento inicia una nueva etapa en la transición `0x60060FE8`, solicitando modo 2, con MMIO virtual 8 y el driver original de fase 66. El registro OEM recibe la instancia **`0x200040E0`**. Ya no se omite `0x6009267C` antes de esa unión.

Sigue siendo una composición por etapas: no se ejecuta todo el código del llamador entre `0x600747B6` y la solicitud posterior de modo 2. La transición hereda el helper sin efectos `0x60060C70`, los modelos del constructor y MMIO ordinario. Se detiene tras la primera clase, con modo transitorio 1; no publica el modo final ni ejecuta callbacks.

## Reproducción y validación

```powershell
python -m tools.audit_pending_workqueue_phase67 local/bruce.bin --out local/phase67.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_pending_workqueue_phase67 -v
```

Requiere `requirements-emulation.txt` y la imagen exacta obtenida por separado del [archivo OEM](https://github.com/StadiaMemories/firmware). El auditor verifica SHA, instrucciones, literales, etiqueta y resultados. Las pruebas negativas alteran la guarda de handle, comparación de tamaño y etiqueta. **742 pruebas locales pasan**, con las pruebas contra el original habilitadas. CI reproduce y compara la evidencia completa; no se publica el firmware ni el snapshot de RAM.

## Límite y continuación

Se resuelve el retorno de la llamada antes pendiente bajo condiciones explícitas y se demuestra por qué la escritura del modo 1 puede preceder a un fallo. Queda pendiente seguir **quién inicializa realmente `0x200201A8` y establece el handle**, así como ejecutar o acotar `0x600CA1F8` y los efectos de sincronización. Tampoco se conoce el valor físico de esos campos.

La activación física de clase 10, ejecución de callbacks desde USB, código propio y elusión HAB siguen sin demostrarse. No se han enviado comandos al mando ni modificado firmware, eFuses o registros físicos.

[Evidencia](../../evidence/usb-pending-workqueue-phase67.json) · [Auditor](../../tools/audit_pending_workqueue_phase67.py)
