# Fase 48 — Objeto global USB, despacho indirecto y ruta condicional EP0 → clase 10

**26/10/2026 · PR #50 · Ingeniería inversa de la actualización OEM Bruce firmada original, sin acceso al mando físico.**

## Resumen de la conclusión

La fase 47 encontró el callback de control EP0 **`0x60054D75`**, su registrador dedicado `0x60054F30` y llamadas hacia el despachador `0x600D0BC8`. En la fase 48 hemos separado **dos caminos de despacho diferentes**:

- **`0x600D0BFA: BLX R3`** toma su destino de un objeto de configuración USB en RAM mediante dos lecturas de punteros, **sin método exacto resoluble en el archivo OEM original**.
- **`0x6005505C`** es un *distribuidor por clase* que el callback EP0 llama en **dos ramas firmadas con evento interno 1**. Recorre registros runtime de 12 bytes, reconoce el selector **10** y elige desde la tabla OEM de métodos de 16 bytes el puntero firmado **`0x600D0E59`** para clase 10, *si* una configuración activa contiene esa clase.

El segundo punto es una cadena estática más concreta para investigar EP0 → clase 10. **No prueba que la clase 10 esté habilitada en hardware ni que un USB host pueda activar la operación.**

## 1. Dirección y semántica del objeto global de EP0

La función firmada **`0x60054F7C`** recibe el objeto USB original en R0, conservado como R5. En **`0x60054F8A`** carga un literal de `0x60054FAC`, cuyo valor original es **`0x20004080`**. En `0x60054F90` lee el puntero guardado en `[0x20004080]` y en `0x60054F92` lo compara con el objeto USB de entrada. Solo si coinciden escribe **`0x20004080`** en el puntero de salida (`0x60054F96`), que el llamador `0x600D0BC8` había situado en la pila.

Otros dos literales que utilizan funciones auxiliares (`0x60054FE8` y `0x60055020`) contienen la misma dirección. **No es un puntero arbitrario introducido por USB.**

### Cinco globales distintas, verificadas como datos firmados

| Componente | Inicializador o lookup OEM | Dirección RAM |
|---|---|---|
| Estructura USB común usada por EP0 | `0x60054F7C` | **`0x20004080`** |
| Clase 1 | `0x600552F0` | `0x200040C0` |
| Clase 2 | `0x60054C7C` | `0x20004040` |
| Clase 4 | `0x60054874` | `0x20004020` |
| Clase 10 | `0x60055320` | **`0x200040E0`** |

La dirección del objeto USB común **no coincide** con ninguno de los cuatro globales de clase. Una hipótesis provisional de coincidencia con clase 1 quedó descartada al verificar todos los literales firmados.

## 2. Lo que realmente hace el BLX de 0x600D0BFA

Tras el lookup correcto, `0x600D0BEE: LDR R3,[SP,#4]` recupera la dirección de la estructura USB común. A continuación:

```asm
0x600D0BF6  LDR R3, [R3,#4]    ; puntero a objeto de configuración
0x600D0BF8  LDR R3, [R3,#4]    ; puntero de método en config+4
0x600D0BFA  BLX R3              ; llamada indirecta
```

El primer campo del objeto de configuración también es utilizado por el distribuidor `0x6005505C`, que lee el puntero a registros runtime de 12 bytes (`config+0`) y el número de registros (`config+8`).

**No se debe sustituir conceptualmente el puntero `config+4` por `0x600D0ECB` solo porque esta última función esté en la tabla ROM de clase 10.** El archivo OEM original **no contiene un snapshot runtime** del objeto de configuración que permita justificar esa sustitución.

## 3. Nuevo enlace confirmado: EP0 invoca el distribuidor de clase con evento 1

La función EP0 firmada `0x60054D74` tiene al menos dos ramas condicionales que colocan el valor **1** en R1 antes de llamar al mismo distribuidor:

```asm
0x60054E08  MOVS R1,#1
0x60054E1A  BL 0x6005505C

0x60054E5A  MOVS R1,#1
0x60054E6A  BL 0x6005505C
```

En `0x6005505C`, los anclajes originales prueban:

- `0x60055060` conserva el evento R1 en R7; `0x60055062` conserva los datos R2 en R6.
- `0x60055072` consulta el singleton USB `0x20004080`.
- `0x6005508A` carga la configuración desde `[singleton+4]`.
- `0x6005508C` lee el número de registros desde `config+8`; `0x60055092` lee el inicio de la tabla desde `config+0`.
- El stride de los registros runtime es **12 bytes**; `0x60055098–9A` extrae el selector de clase de `[registro+8]+4`.
- `0x600550A8: CMP R3,#0x0A` reconoce expresamente la clase 10.
- `0x60055082` carga un literal firmado desde **`0x600550E0`** que contiene la tabla ROM de métodos **`0x60104B74`**. Los registros ROM ocupan **16 bytes** cada uno.
- Para clase 10, el índice de método ROM es **3** y `0x600550BA` lee el puntero **`[registro_ROM+8]`**. Ese puntero, verificado en `0x60104BAC`, es **`0x600D0E59`**, invocado con `0x600550BC: BLX R3`. El evento 1 se restituye con `0x600550B6: MOV R1,R7`.

La función `0x600D0E58` es el forwarder que, cuando recibe evento 1, va a `0x600D0EA2` y procesa campos SETUP-like y `bRequest`, como se verificó en las fases 45 y 46.

### Condiciones no resueltas

Para convertir esta ruta estática en ejecución USB real necesitamos saber si la configuración activa incluye un registro runtime cuyo descriptor indica clase 10, si el objeto clase 10 y callback secundario están realmente registrados y si los eventos EP0 físicos satisfacen las ramas precedentes.

**La presencia del método `0x600D0E59` en la tabla firmada no demuestra por sí sola que el controlador lo invoque en hardware.** Ningún paquete USB, volcado live RAM, escritura de flash/eFuses, bypass HAB CLOSED o firmware propio ha sido ejecutado.

## 4. El trabajo que conviene realizar a continuación

**Fase 49 propuesta:** investigar quién construye el objeto de configuración `[0x20004080+4]`, quién escribe su puntero `config+4` invocado por `0x600D0BFA`, y si contiene en tiempo de ejecución registros de clase 10. La evidencia deberá distinguir registros de arranque, el conjunto de clases de la configuración activa y el callback secundario de clase 10. Si es necesario contrastar hardware, empezar por observación pasiva y recuperable, **sin escribir flash ni eFuses**.

## Entregables reproducibles

```bash
python -m unittest tests.test_bruce_ep0_class_object_phase48 tests.test_bruce_class_singleton_phase48 tests.test_bruce_ep0_class10_fanout_phase48 -v
python -m tools.audit_bruce_ep0_class_object_phase48 local/bruce_pvt_a_prod_signed.bin --out local/phase48-object.json
python -m tools.audit_bruce_class_singleton_phase48 local/bruce_pvt_a_prod_signed.bin --out local/phase48-singletons.json
python -m tools.audit_bruce_ep0_class10_fanout_phase48 local/bruce_pvt_a_prod_signed.bin --out local/phase48-fanout.json
```

La CI comprueba SHA-256 exacto **`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`** y ejecuta pruebas en Python 3.11 y 3.12. [Ver PR #50](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/50).
