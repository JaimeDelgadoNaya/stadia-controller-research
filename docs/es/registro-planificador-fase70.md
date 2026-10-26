# Fase 70 — Registro original en listas y estado de sección crítica

**26 de octubre de 2026.** Auditoría offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 69](handle-tarea-original-fase69.md).

## Resultado principal

**`0x600C9FD8` ya no es un stub.** Se ejecutan sus instrucciones originales y los helpers de lista/sección crítica que alcanza mediante veneers y código ITCM reubicado desde el archivo OEM. La estructura de tarea **`0x20020278`** queda enlazada en la lista virtual de prioridad 1, con contador y bitmap actualizados.

Se siguen sin ejecutar el arranque del planificador, una conmutación de contexto ni la entrada preparada `0x60101760`. **Insertar un nodo no demuestra que la tarea esté ejecutándose.** Los globales iniciales del planificador son un modelo virtual vacío, no los de un mando en funcionamiento.

## Código ITCM ejecutado

Los bytes firmados se copian desde el offset `0x81C` del archivo a sus direcciones de ejecución ITCM. No se interpretan las llamadas relativas usando las direcciones donde esos bytes están almacenados en flash.

| Veneer XIP | Destino Thumb original | Uso observado |
|---|---|---|
| `0x6013D360` | `0x00007D65` | Entrada en sección crítica |
| `0x6013D000` | `0x00007DAD` | Salida de sección crítica |
| `0x6013D060` | `0x0000B2E9` | Inicialización de listas |
| `0x6013D188` | `0x0000B2FF` | Inserción de nodo |

Las cuatro rutinas se ejecutan, incluidas sus cargas, stores, instrucciones de máscara de CPU y retornos. La página de sistema `0xE000E000` es memoria virtual ordinaria: no hay NVIC real, interrupciones asíncronas ni temporización de hardware.

## Resultados del registro con globales virtuales vacíos

| Campo observado | Dirección/estructura | Resultado |
|---|---|---|
| Contador de tareas | `0x200276A0` | 1 |
| Puntero global usado como tarea actual | `0x20027410` | `0x20020278` |
| Bitmap de prioridades preparadas | `0x200276B4` | `0x2` |
| Lista de prioridad 1 | `0x20027430` | Contador 1 |
| Nodo de la tarea | `0x2002027C` | Enlaces de siguiente/anterior del head apuntan al nodo |
| Contenedor del nodo | `0x2002028C` | `0x20027430` |

El original inicializa las listas e inserta el nodo, y la ruta superior publica el handle generado en fase 69. La palabra virtual de estado de planificador `0x20027700` es cero: **no se afirma haber ensayado la inserción en un sistema real ya en ejecución**, ni todas las ramas de prioridad/preempción.

## Sentinela OEM frente a vector de contador cero

Los datos inicializados firmados contienen **`0xAAAAAAAA` en `0x20003D68`**, que las rutinas ITCM usan como contador de sección crítica. Se comparan dos ejecuciones independientes:

| Entrada del contador | Procedencia | Contador al retorno | BASEPRI virtual al retorno |
|---|---|---|---|
| `0xAAAAAAAA` | Bytes inicializados OEM copiados al modelo | `0xAAAAAAAA` | **`0x50`** |
| 0 | Vector de prueba impuesto explícitamente | 0 | **0** |

El helper de entrada incrementa el contador y establece la máscara; el de salida decrementa y solo limpia BASEPRI cuando llega a cero. El primer resultado es coherente con esas instrucciones. **No se presenta como un defecto ni como estado instalado:** no se ha seguido todavía dónde se normaliza ese sentinela durante el arranque completo.

Esto evita una inferencia incorrecta: que retornar del registro garantice siempre que la máscara de interrupciones sea cero.

## Continuación por etapas y límites

Solo la RAM del **vector de contador cero** se entrega a la etapa posterior de transición/driver/clase 10, que vuelve a enlazar la instancia `0x200040E0` con MMIO virtual 8. El caso del sentinela se conserva como experimento independiente; no se asume normalización real del contador.

Esa continuación usa una nueva máquina virtual y contexto de registros, como las fases previas. No transporta un contexto de CPU físico entre etapas. Mantiene los modelos de constructor profundo `0x6013D3D0`, sincronización/registro exterior, relleno de bytes y helper de transición. Se detiene antes de la publicación final del modo y de ejecutar otras clases o callbacks.

## Reproducción

```powershell
python -m tools.audit_scheduler_registration_phase70 local/bruce.bin --out local/phase70.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_scheduler_registration_phase70 -v
```

Requiere `requirements-emulation.txt` y el archivo exacto del [archivo OEM](https://github.com/StadiaMemories/firmware). Se verifica SHA, instrucciones del registro, destinos de veneers y sentinela de datos. Se comprueban enlaces, contadores, bitmap y ambos resultados de máscara. Las pruebas negativas alteran la llamada de inserción, un destino ITCM y el sentinela. **754 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce toda la evidencia. La salida anterior de fase 69 se mantiene con las opciones por defecto.

## Siguiente frontera

Queda por seguir la **normalización del contador `0x20003D68`**, el arranque/context switch del planificador y el flujo de trabajo de `0x60101760`. Los resultados actuales son registros y enlaces originales en memoria virtual, no tareas ni eventos USB observados en hardware.

No se han enviado comandos al mando, modificado firmware/eFuses, ejecutado código propio en el dispositivo ni superado HAB CLOSED. La activación física de clase 10 permanece sin demostrar.

[Evidencia](../../evidence/usb-scheduler-registration-phase70.json) · [Auditor](../../tools/audit_scheduler_registration_phase70.py)
