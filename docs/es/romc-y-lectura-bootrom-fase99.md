# Fase 99 — ROMC temporal y búsqueda de una lectura de BootROM interna

**24/11/2026. Estado: auditoría offline; ninguna operación física realizada.**

## A. Contrato exacto del código fuente que envió el propietario

Se reabrió y analizó `nxp-sdp-overrun-main.zip`, `main.py` SHA-256 `e41e659f25388578ef9b2c1a1800adecf9e290d5ec0b57fbabb8705c3f765404`, sin importarlo ni ejecutarlo.

La rama **por defecto** es `SHELLCODE_ROMC`. Restauraría el puntero original `sdp_dev` antes de escribir los cuatro registros ROMC. Las direcciones se obtienen directamente de las constantes y desplazamientos del script, no de una lectura del mando:

| Concepto en código del autor | Dirección |
|---|---|
| ROMPATCH0D: palabra de datos que sustituye la lectura ROM | `0x401800F0` |
| ROMPATCH0A: dirección de comparación | `0x40180100` |
| ROMPATCHENL: activación del comparador | `0x401800FC` |
| ROMPATCHCNTL: parche tipo data-fix | `0x401800F4` |

La palabra ARM Thumb prevista es `0x477020F0`: `movs r0,#0xF0; bx lr`. El objetivo es que la función de consulta de configuración HAB responda como si estuviera abierta para operaciones posteriores de **la misma sesión**; **no** sustituye una imagen en flash, no cambia SRK/fusibles, no prueba salto ejecutado ni desactiva permanentemente la autenticación. El autor distingue claramente la opción irreversible `SHELLCODE_FIELD_RETURN`/OCOTP, **NO-GO**.

En el host, el mensaje de éxito solo depende de que `hid.write` devuelva la longitud prevista. **No acredita ejecución en Cortex-M7 ni aceptación posterior de un binario sin firma**.

[Auditor del origen sin importación/ejecución](../../research/phase99/romc_source_contract.py) · pruebas sintéticas de puertas de verificación.

## B. Nuevo hallazgo en el cargador Google firmado

El cargador RAM original, SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`, ya medido anteriormente en el mando, expone `ReadMemory` (tag 3, `0x200035A5` Thumb) como comando **habilitado**. `Execute`/ `Call` están **deshabilitados** en la tabla de despacho ordinaria (fase previa `docs/en/loader-execution-gate.md`).

La nueva auditoría descargó **solo en GitHub Actions** la muestra pública y la verificó por hash antes de desensamblar una ventana del manejador; se observa una llamada a `0x200039F4` desde `0x20003686`. La función de `0x200039F4` accede a una lista de rangos a través de:

```
0x20003A38 (literal en binario original)
    -> 0x202081F4 (global del cargador)
    -> [0x202081F8] = 0x202087BC
    -> tabla de registros inicializada
```

La segunda flecha se **reconstruye mediante la copia de inicialización firmada** `0x200164D8 → 0x20208000` de 0x830 bytes (no se ha leído RAM real hoy). El recorrido no prueba la ausencia de mutaciones posteriores.

### Tabla reconstruida desde el archivo firmado

Seis registros de cuatro palabras cada uno, más registro de terminación con ceros (el formato exacto de límites y campos depende del tipo de memoria):

| Campo 1 | Campo 2 | Campo 3 | Campo 4 |
|---|---|---|---|
| `0x00000000` | `0x0001FFFF` | `0x11` | `0x20015EA8` |
| `0x20000000` | `0x2001FFFF` | `0x11` | `0x20015EA8` |
| `0x20200000` | `0x2023FFFF` | `0x11` | `0x20015EA8` |
| `0x60000000` | `0x6FFFFFFF` | `0x00` | `0x20015FB8` |
| `0x90000000` | `0x01000000` | `0x00` | `0x20016024` |
| `0x40000000` | `0x403FFFFF` | `0x20` | `0x20015E74` |
| `0x00000000` | `0x00000000` | `0x00` | `0x00000000` |

**Nuevo resultado negativo importante:** **ninguno de los registros inicializados incluye explícitamente la dirección de BootROM interna `0x00200000–0x0021FFFF`**, aunque el comando `ReadMemory` figure habilitado. El registro `0x90000000,0x01000000` es un caso con un segundo campo aparentemente de longitud, no necesariamente dirección final: **no** interpretarlo indiscriminadamente como límite superior.

**Clasificación:** *la lectura ordinaria de la ROM interna mediante el cargador firmado no está justificada por esta tabla; probablemente sea rechazada en la ruta verificada.* Esto es una inferencia de análisis estático, **no un rechazo real medido**. No se ha demostrado que el firmware no altere el puntero durante la sesión ni que no existan otras vías autorizadas de lectura.

- [Auditor de código y despacho](../../research/phase99/audit_signed_readmemory.py).
- [Reconstrucción limitada de la tabla y punteros](../../research/phase99/trace_read_policy.py).
- [GitHub Actions #45356121721](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45356121721): descarga, SHA-256, desensamblado y salida textual, **SUCCESS**.

## C. Decisión para firmware personalizado

- **Candidato de prioridad alta**: esperar evidencia o código del port Stadia/Zephyr que el autor `tchebb` afirma tener; no hay release verificable del port al corte de esta fase. [Declaración original](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/).
- **Bloqueo físico**: no sabemos si BootROM RT1061 de la unidad comparte las instrucciones vulnerables de la ROM RT1060 que verificamos en fase 98.
- **No propuesta de ejecución física**: no probar `--permanent`, no programar fusibles, no modificar flash ni convertir una hipótesis de lectura en una prueba sobre el único mando.
- **Pruebas offline locales**: 16/16 comprobaciones del modelo ROMC y del despacho sintético del loader. La CI repite por separado 12 tests sintéticos más la inspección del original firmado. No se suman artificialmente como pruebas de exploit en dispositivo.

**Resultado de fase 99: entendemos mejor la ruta temporal y hemos identificado un probable límite de lectura de ROM por la vía OEM firmada. No hemos logrado aún ejecutar firmware personalizado en el Stadia.**
