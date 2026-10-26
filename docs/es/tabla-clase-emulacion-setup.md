# Fase #37 — Registros de clase Bruce y prueba ARM del reenvío de SETUP

**26 de octubre de 2026.** Todos los resultados de esta fase proceden de la **imagen pública OEM Bruce original firmada**, 1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No se ha usado el dispositivo físico ni se ha enviado tráfico USB. **No es un volcado de la flash instalada.**

La [fase #35](setup-control-clase-bruce.md) identificó el reenvío condicional del campo `bRequest` hacia un callback por `0x600D0EBA → BX R3`. La [fase #36](bruce-referencias-tablas-clase.md) descartó que la referencia `0x60104BDC` a una tabla indexada de ocho bytes fuera prueba de la instalación del callback de clase `0x600D0E58`.

## 1. Nueva estructura comprobada en los datos originales

La lectura en palabras de 32 bits de la imagen firmada permite agrupar el intervalo `0x60104B80..0x60104BBF` en cuatro **registros aparentes de 16 bytes**:

| Inicio | Selector (palabra) | Función 1 | Función 2 | Función 3 |
|---|---|---|---|---|
| `0x60104B80` | `1` | `0x60054C7D` | `0x60054D09` | `0x60054A55` |
| `0x60104B90` | `2` | `0x60054875` | `0x600D0591` | `0x600D0333` |
| `0x60104BA0` | `4` | `0x60055321` | `0x600D0ECB` | **`0x600D0E59`** |
| `0x60104BB0` | `10` | `0` | `0` | `0` |

Las nueve funciones de los primeros tres registros son punteros Thumb dentro del código de aplicación firmado. El último registro es un **registro con funciones nulas**; su papel (fin de tabla, valor reservado, etc.) está por verificar.

Este patrón hace plausible la existencia de un **registro de controladores/objetos de clase** y aporta una posible frontera de registro más concreta: `0x60104BA0`, en vez de considerar `0x60104BA4` comienzo probado de tabla. Es una interpretación estructural **offline**, no evidencia de selección del registro `4` ni instalación en EP0.

La búsqueda exacta de palabras que contengan las direcciones de los posibles registros (incluida la zona de código trasladada a ITCM) no encontró referencias directas a `0x60104B80`, `0x60104B90` ni `0x60104BA0`. Una búsqueda más amplia de cargas literales PC-relativas detectó un candidato en `0x60058820`, pero el literal vale `0x60104C38`: **fuera del grupo anterior**. Por tanto, tampoco demuestra su utilización.

**Límite:** las direcciones pueden calcularse, pasarse indirectamente, copiarse de otra región o no utilizarse en el modo de firmware bajo estudio. Una búsqueda negativa no prueba que el código sea inalcanzable.

## 2. Emulación real de la rama original de clase

Herramienta: `tools/emulate_bruce_class_request_fragment.py`, Unicorn 2.1.4, ARM Thumb/M-class. Se verifica **SHA-256 y longitud** antes de ejecutar ningún byte original.

Se carga la imagen OEM en una región **virtual** que representa XIP y se crean en RAM virtual un objeto de clase, un puntero a búfer SETUP, un búfer sintético de ocho bytes y una palabra que contiene un **callback ficticio**. Se comienza deliberadamente en **`0x600D0EA2`**, *después* del despacho de eventos `1..4`. **No se demuestra que el evento real de EP0 llegue a este punto.**

La emulación detiene la CPU **ANTES** de ejecutar `BX R3` en `0x600D0EBE`; registra los argumentos que habría recibido la función apuntada, sin ejecutarla ni instalarla.

| SETUP sintético | Resultado comprobado | PC de detención | Argumento `R1` |
|---|---|---|---|
| `A1 81 00 00 01 00 00 00` | Reenvía | `0x600D0EBE` | `0x81` |
| `21 83 00 00 01 00 00 00` | Reenvía | `0x600D0EBE` | `0x83` |
| `A1 84 00 00 01 00 00 00` | Reenvía | `0x600D0EBE` | `0x84` |
| `A0 81 00 00 01 00 00 00` | Descarta por destinatario | `0x600D0E76` | No se invoca callback |
| `A1 84 00 00 02 00 00 00` | Descarta por índice de interfaz | `0x600D0EC6` | No se invoca callback |

En los tres ejemplos admitidos, `R3` era el valor de función **sintético** `0x20003001`; `R1` contenía el `bRequest` esperado. Cada caso procesó **14 instrucciones** para llegar al límite de despacho. La emulación no ejecutó el callback ficticio.

### Interpretación correcta

**Está demostrado para esa rama aislada, con entradas construidas artificialmente, que los códigos `0x81`, `0x83` y `0x84` no se filtran antes de reenviarse al callback** si el destinatario e índice coinciden. La rama inspeccionada verifica el destinatario pero **no autentica ni interpreta** por sí misma esos códigos. La decisión y los efectos corresponden al manejador al que se saltaría.

**No está demostrado:** que esa instancia exista realmente en el mando de producción, que el código sea alcanzado por las transferencias del actualizador, qué dirección contiene la tabla real de clase, qué operaciones permitiría, ni que exista una ejecución de código modificable por el host.

El `BX R3` usa una dirección obtenida del **objeto de clase**, no un puntero enviado directamente por USB. Este trabajo **no** acredita ejecución arbitraria, bypass HAB CLOSED, código propio persistente, recuperación o compatibilidad Xbox/Switch 2.

## 3. Reproducción y salvaguardas

```sh
python -m pip install -r requirements-emulation.txt
python -m unittest tests.test_bruce_class_object_origins tests.test_bruce_class_request_fragment -v
python -m tools.audit_bruce_class_object_origins local/bruce_pvt_a_prod_signed.bin --out local/class-origins.json
python -m tools.emulate_bruce_class_request_fragment local/bruce_pvt_a_prod_signed.bin --out local/emulated-setup.json
```

El workflow de GitHub Actions obtiene temporalmente la **copia OEM pública** con hash verificado, ejecuta auditores y Unicorn en una VM aislada, publica solo resultados en consola y elimina la imagen y los JSON efímeros. **No se envía USB, no se escribe en el mando ni se ejecuta un callback externo.**

**Criterio para la fase siguiente:** identificar el procedimiento que carga el registro de selector `4` en el objeto realmente usado por EP0 y el destino real del puntero `[R0+4]→[puntero]`. Hasta entonces, no enviar solicitudes nuevas o de escritura al único dispositivo físico.

[PR #37](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/37).
