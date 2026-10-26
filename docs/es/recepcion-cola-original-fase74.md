# Fase 74 — Entrada original del receptor de Work Queue y frontera de espera

**26/10/2026.** Auditoría exclusivamente offline de la actualización OEM Bruce original firmada (SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). Continúa la [fase 73](entrada-tarea-modelo-retorno-fase73.md).

## Hallazgo principal

La tarea OEM había llegado al `BL` de `0x600EE152`, sin ejecutarlo. Ahora se ha reconstruido y ejecutado **solo el prólogo original de recepción**, usando el estado virtual heredado de la fase 73, sin inyectar mensajes ni introducir una respuesta artificial de cola.

```text
0x600EE152   BL 0x6013D268      (worker OEM)
0x6013D268   LDR.W PC,[PC,#-0] (veneer original firmado XIP)
0x6013D26C   literal 0x00006D2D (palabra de DATOS; bit Thumb)
0x00006D2C   receptor original ITCM (bytes firmados relocalizados)
...
0x00006D58   BL 0x7734         (PRIMER LÍMITE: NO EJECUTADO)
```

El archivo OEM contiene la copia inicial de ITCM a partir del offset `0x81C`; el código `0x6D2C` proviene del offset **`0x7548`**. Se cargaron esos bytes firmados en la región virtual ITCM. El primer intento falló precisamente porque la máquina virtual heredada **no tenía mapeada** esta región; se corrigió el *harness* sin cambiar el archivo OEM ni tocar el mando.

El auditor verifica **13 anclas del firmware original**: la instrucción veneer, su literal y 12 instrucciones de recepción (prólogo, guardas, comprobación del contador y bifurcación de espera). La ejecución original preserva los argumentos de la llamada:

| Registro / campo | Valor virtual observado |
|---|---|
| R0: control de cola | `0x200201AC` |
| R1: búfer de salida | `0x20020B1C` |
| R2: espera | `0xFFFFFFFF` |
| R4 después del prólogo | `0x200201AC` |
| R7 después del prólogo | `0x20020B1C` |
| Palabra de espera guardada en stack | `0xFFFFFFFF` |
| Búfer antes y después | `0xA5A5A5A5` (sin cambios) |

La secuencia ejecutada en Unicorn es `0x600EE152 → 0x6013D268 → 0x6D2C → 0x6D30 → 0x6D32 → 0x6D34 → 0x6D36 → 0x6D38 → 0x6D46`, y **se detiene antes de `0x6D58`**. Esto acredita el paso por las dos guardas de argumentos con los datos virtuales heredados.

## Condiciones originales de recepción localizadas, pero no ejecutadas

El desensamblado firmado muestra:

```asm
0x6D7A  LDR R5,[R4,#0x38]       ; contador
0x6D7C  CBZ R5,#0x6DB4          ; si cero, ruta sin elementos
0x6DB4  LDR R5,[SP,#4]          ; timeout conservado
0x6DB6  CBNZ R5,#0x6DC0        ; si timeout no cero, rama de espera
```

La captura de la **RAM virtual** muestra `[0x200201AC+0x38] = 0`, y la espera preparada es `0xFFFFFFFF`. **Si esos valores persisten** después de las primitivas de sincronización intermedias, el programa tomaría la ruta de cola vacía y espera. **Es una predicción estática condicionada, no una rama ejecutada.**

No se ha llamado a `0x7734`, `0x7D64` ni a los helpers posteriores: no se ha adquirido sincronización, bloqueado/despertado una tarea, extraído ningún mensaje ni invocado callbacks.

## Por qué importa

1. El receptor ya no es una dirección desconocida: tenemos un destino firmado preciso, estructura de argumentos y puntos de ramificación del flujo de recepción.
2. La **cola virtual modelada está vacía** en la captura; inventar un elemento para avanzar produciría un falso positivo.
3. Para seguir la cadena USB → Work Queue → callback hay que **identificar un productor real de mensajes** y verificar su formato antes de ejecutar una ruta de recepción con datos.

## Próxima fase

Priorizaría la **fase 75**: investigar los productores del control de cola `0x200201AC` y los llamadores de las primitivas de envío, rastreando si alguno procede de EP0, clases USB, interrupciones o trabajo interno. La continuación del receptor `0x7734 → 0x7D64 → ...` necesitaría modelos limitados y explícitos de sincronización/planificación, y debería esperar a identificar un mensaje genuino.

**No existe todavía prueba de paquete USB físico → elemento de cola → callback, ni de activación física de clase 10, ejecución de firmware propio o bypass HAB CLOSED.**

## Reproducir

```powershell
python -m pip install -r requirements-emulation.txt
python -m tools.audit_queue_receive_phase74 local/bruce.bin
python -m tools.execute_queue_guards_phase74 local/bruce.bin --out local/phase74.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_queue_receive_phase74 tests.test_queue_receive_guards_phase74 -v
```

La auditoría exige longitud/hash exactos y compara el resultado contra [evidencia estructurada](../../evidence/usb-queue-receive-phase74.json). [PR #76](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/76). Todo es offline: no se envían peticiones USB ni se escribe flash/eFuses.
