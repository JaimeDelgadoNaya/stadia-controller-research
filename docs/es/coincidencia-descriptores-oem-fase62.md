# Fase 62 — Coincidencia exacta del descriptor físico con Bruce OEM

**26 de octubre de 2026.** Comparación offline de la enumeración física de fase 61 con la imagen OEM de 1.050.984 bytes cuyo SHA-256 es `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Resultado principal

Los **80 bytes completos** del descriptor de configuración leído al hub aparecen exactamente una vez en el contenido autenticado inspeccionado de la aplicación OEM: desplazamiento de archivo **`0xDE45A`**, dirección XIP **`0x6011E45A`**. No se trata solo de endpoints parecidos: coincide toda la secuencia medida. Esto enlaza la superficie USB observada con una tabla concreta del archivo OEM; **no equivale a verificar el hash de toda la aplicación instalada**.

La vista WinUSB de 32 bytes **no aparece como secuencia exacta** en ese contenido. La imagen sí contiene otro descriptor de solo fabricante, pero mide **40 bytes** e incluye una asociación de interfaz. No debe confundirse con la vista parcial de Windows. La diferencia de vistas se midió en fase 61; esta búsqueda no identifica por sí sola la capa exacta de Windows que la produce.

## Cuatro perfiles, todos con bConfigurationValue = 1

La rutina firmada que comienza en **`0x600619BC`** escribe un puntero de descriptor y su longitud en `[R1]` y `[R1+4]`. Los siguientes perfiles son sus cuatro salidas verificadas:

| Dirección XIP del descriptor | Longitud | Interfaces distintas | Clases USB | Coincide con la lectura del hub |
|---|---:|---:|---|---|
| `0x6011E45A` | 80 | 2 | `FF`, `03` | Sí, exactamente |
| `0x6011E4AA` | 40 | 1 | `FF` | No |
| `0x6011E4D2` | 204 | 4 | `FF`, `03`, `01` | No |
| `0x6011E59E` | 287 | 5 | `FF`, `03`, `01` | No |

Los dos últimos añaden interfaces de clase audio `0x01`, con alternate settings e interfaces de streaming. No se han probado audio, selección de perfil ni cambios de configuración en el mando. Son perfiles alternativos dentro del archivo, **no cuatro valores de SET_CONFIGURATION que pueda elegir libremente el host**.

## Condiciones de selección verificadas

La primera llamada obtiene un objeto mediante `0x6005BDAC`. Después, `0x600DFFE8` recibe ese retorno más `0x448`, y el argumento `7`. Su significado y sus efectos no están resueltos en esta fase. Se denomina **H** a su retorno.

Si H es cero, el código consulta bytes de SRAM **A = `0x2000A804`** y **B = `0x2000A805`**, calculados desde el literal original `0x200064C0` y offsets `0x4344/0x4345`:

| Condición del código OEM | Salida |
|---|---|
| H distinto de cero | 40 bytes |
| H = 0, A = 0 | 80 bytes; B no se consulta |
| H = 0, A distinto de cero, B = 0 | 204 bytes |
| H = 0, A distinto de cero, B distinto de cero | 287 bytes |

Esto **no es una lectura de A, B o H en el mando**. Solo de forma condicional, si esta rutina sin cambios es la que produjo la enumeración medida, su salida de 80 bytes es coherente con H = 0 y A = 0. No se ha demostrado quién escribe los bytes, qué representan, si el host puede alterarlos ni si esta rutina está en la ruta activa instalada.

## Emulación y validación

Unicorn ejecuta las instrucciones originales de `0x600619BC..0x60061A2C` con límite de 200 instrucciones, ocho combinaciones sintéticas H/A/B en `{0,1}`, stack y destino de salida sintéticos. Se interceptan tres funciones: obtención del objeto, comprobación H y logging. No se ejecutan sus implementaciones; no se modela un SoC completo. La evidencia registra cada llamada interceptada, puntero final, longitud y retorno.

Los ocho casos retornan cero y producen el puntero y longitud esperados. El auditor exige el hash de la imagen, comprueba instrucciones clave, literales PC-relativos, longitudes y estructura de los cuatro descriptores. Una prueba negativa sustituye el PUSH inicial por NOP y verifica que se rechazan tanto la deriva semántica como el hash modificado. Las **720 pruebas locales** pasan, incluida la prueba opcional contra la imagen OEM exacta. El workflow dedicado reproduce la evidencia completa y la compara con el JSON publicado.

```powershell
python -m tools.audit_usb_descriptor_match_phase62 local/bruce.bin --emulate --out local/phase62.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_descriptor_match_phase62 -v
```

Dependencias: `requirements-emulation.txt`. Crear `local/` y obtener por separado la imagen del [archivo de StadiaMemories](https://github.com/StadiaMemories/firmware); el auditor rechaza cualquier hash distinto del indicado. El archivo OEM no se añade al repositorio ni a los artefactos públicos. La medición física proviene de [fase 61](enumeracion-usb-fase61.md); el resto de esta fase es offline.

## Decisión y siguiente paso

Se sustituye la mera coincidencia de endpoints por una **coincidencia completa y única del descriptor** y una **ruta OEM condicional que lo devuelve**. Sigue sin probarse activación del selector interno 10, invocación de `0x2000FBF4/0x2000FBF8`, ejecución propia, elusión HAB o compatibilidad directa con consolas.

La continuación concreta es seguir los llamadores de `0x600619BC` y los escritores de A/B en el archivo autenticado, hasta relacionar este proveedor de descriptores con el objeto de configuración/registro de clases. No es suficiente renombrar VID/PID ni asumir que el descriptor público revela los punteros internos de RAM.

[Evidencia reproducible](../../evidence/usb-descriptor-oem-match-phase62.json) · [Auditor](../../tools/audit_usb_descriptor_match_phase62.py)
