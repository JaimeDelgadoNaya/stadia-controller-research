# Fase #38 — selección real de clases USB en Bruce y corrección del registro 10

**26 de octubre de 2026.** Todas las direcciones se han examinado sobre el archivo de actualización **OEM Bruce original firmado** (1.050.984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). No es lectura de la flash instalada en el controlador, ni se ha conectado o modificado el mando.

## 1. Hallazgo: la base de la tabla sí aparece en código ejecutable firmado

La fase #37 agrupó palabras de 16 bytes equivocadamente: consideró que el selector estaba en la primera posición. El código real de selección desmiente esa interpretación.

Las dos instrucciones `0x60055142 LDR.W FP,[PC,#0x70]` y `0x600551CC LDR.W SB,[PC,#0x50]` cargan literales en `0x600551B4` y `0x60055220`, respectivamente. **Ambos literales contienen `0x60104B74`**: la base real de una tabla de cinco registros de 16 bytes.

En `0x60055178–0x6005519A` se lee el selector `[base+offset+0x0C]`, se compara con un campo de datos de configuración, y, si coincide, se carga una función desde `[base+offset]` y se llama con `BLX R3`. El desplazamiento aumenta en `0x10` hasta alcanzar `0x50`: **cinco entradas**.

Una segunda ruta `0x600551FC–0x6005521A` carga la misma tabla, lee un método desde `[entrada+4]` y llama mediante `BLX R2`; también recorre cinco entradas. El código `0x600552D0–0x600552DC` calcula `índice<<4` y compara el primer byte con el selector del objeto. Se observan por tanto **tres mecanismos de direccionamiento/comparación** compatibles con la misma estructura de 16 bytes; la relación dinámica exacta de la tercera ruta no está probada.

## 2. Formato correcto verificado contra la imagen original

Cada entrada tiene tres punteros Thumb en posiciones `+0`, `+4`, `+8` y su selector en `+0x0C`:

| Base | Método +0 | Método +4 | Método +8 | Selector +12 |
|---|---|---|---|---|
| `0x60104B74` | `0x600552F1` | `0x600D0DFD` | `0x600D0C6B` | 1 |
| `0x60104B84` | `0x60054C7D` | `0x60054D09` | `0x60054A55` | 2 |
| `0x60104B94` | `0x60054875` | `0x600D0591` | `0x600D0333` | 4 |
| `0x60104BA4` | `0x60055321` | `0x600D0ECB` | **`0x600D0E59`** | **10** |
| `0x60104BB4` | 0 | 0 | 0 | 0 |

**Corrección esencial:** el manejador `0x600D0E58` de `bRequest` es **el método +8 del registro selector 10**. **No es del registro 4**. La lectura de palabras firmadas, los literales PC-relativos y las instrucciones que utilizan el stride/offset se comprueban con anclas de Capstone y pruebas automatizadas. Las descripciones de la fase #37 y su JSON se han corregido explícitamente.

El registro 10 tiene además como primer método `0x60055320` (rutina que copia el argumento `R1` a un campo `[objeto+4]` durante la inicialización), y como segundo `0x600D0ECA` (limpieza). El contenido de ese argumento en un mando activo sigue **sin conocerse**; no se puede concluir que el ordenador lo pueda modificar.

## 3. Verificación dinámica limitada en Unicorn con código original

Se ha ejecutado **solo** la porción `0x60055178–0x60055192` del binario original con RAM y configuraciones inventadas, parando **ANTES de `0x60055194 BLX R3`**.

| Descriptor sintético | Entrada inspeccionada | Resultado |
|---|---|---|
| Selector 4 | Registro 4 | Coincide → método Thumb `0x60054875` |
| Selector 10 | Registro 10 | Coincide → método Thumb `0x60055321` |
| Selector 10 | Registro 4 | No coincide → ruta de descarte |
| Selector 4 | Registro 10 | No coincide → ruta de descarte |

En ambos casos positivos se ejecutaron 13 instrucciones originales antes de detener el emulador. **Ningún método de clase se ejecutó**. Esta prueba demuestra la correspondencia de identificador y registro *dentro de un estado sintético*, no que el dispositivo configure realmente la clase 10.

La fase #37, de manera independiente, había emulado `0x600D0EA2–0x600D0EBE` con un objeto sintético y demostrado que entrega `bRequest 0x81/0x83/0x84` al callback si destinatario e interfaz coinciden. **La combinación de ambos experimentos NO constituye una cadena de ejecución real completa**: no se ha enlazado el objeto físico EP0, ni el argumento/callback instalado en RAM, ni la función final a la que saltaría `BX R3`.

## 4. Datos inicializados y búsqueda previa

La sección de datos que se copia en el arranque (`0xFD5A8` → RAM `0x20002740`, longitud 6296 bytes) no contiene referencias directas alineadas a la base `0x60104B74`, al registro `0x60104BA4` o a los tres métodos del selector 10. Esta ausencia **no es evidencia de no utilización**, porque la base está claramente referenciada directamente en código XIP y la estructura puede usar RAM creada durante el arranque.

Los resultados de la fase #36 que buscaban literalmente el supuesto comienzo `0x60104BA4` eran correctos para esa dirección, pero **no cubrían la dirección real de base `0x60104B74`**. Por eso aquella conclusión negativa nunca descartó una referencia al registro verdadero.

## 5. Qué falta para conseguir el objetivo

**Demostrado:** tabla real y dos referencias a su base, cinco registros, identificador 10 asociado a `0x600D0E58`, selección por identificador en código firmado y comportamiento aislado en Unicorn.

**No demostrado:** modo/clase 10 realmente activos en el mando físico, enlace de una petición USB host a ese objeto, contenido del callback que se almacena en RAM, efectos concretos de `0x81/83/84`, una vía para ejecutar nuestro firmware, bypass HAB CLOSED, restauración tras error o compatibilidad directa Xbox/Switch 2.

**Siguiente objetivo acotado:** seguir en el inicializador de clase 10 cómo se determina el puntero `R1` entregado a `0x60055320`, y su primera palabra `[R1]`; comprobar si la fuente es un objeto firmado/estático o un callback de configuración. No experimentar con comandos de escritura en el mando sin una recuperación validada.

## Reproducción

```sh
python -m pip install -r requirements-emulation.txt
python -m unittest tests.test_bruce_class_selector tests.test_bruce_class_selector_verified tests.test_emulate_bruce_class_selector tests.test_bruce_class_object_origins -v
python -m tools.audit_bruce_class_selector_verified local/bruce_pvt_a_prod_signed.bin
python -m tools.emulate_bruce_class_selector local/bruce_pvt_a_prod_signed.bin
```

La acción `.github/workflows/signed-app-host-boundary.yml` verifica la copia OEM original mediante SHA-256, ejecuta todo en un runner aislado y elimina las entradas temporales; no publica binarios, no envía USB y no modifica el controlador.

[PR #38](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/38).
