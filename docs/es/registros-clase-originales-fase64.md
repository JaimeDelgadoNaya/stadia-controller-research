# Fase 64 — Los cuatro productores y la inclusión de clase interna 10

**26 de octubre de 2026.** Auditoría offline de la imagen Bruce OEM exacta, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 63](proveedor-usb-inicializacion-fase63.md).

## Resultado principal y cambio de conclusión

**El inicializador OEM construye un array con selectores internos 10, 1, 2 y 4, en ese orden**, bajo las condiciones de ejecución modeladas. Se han identificado los cuatro objetos y métodos productores y se han ejecutado sus instrucciones originales. Los registros ya no son los ceros sintéticos de fase 63: proceden de los datos inicializados de la imagen OEM firmada.

La primera entrada incorpora el registro de clase 10 previamente identificado en fases 40–43. Una ejecución acotada del selector original, con este array, alcanza el método Thumb **`0x60055321`**, con **R1=`0x2000A274`** y R2=`0x2000A278`. Se detiene **antes** del BLX que ejecutaría el inicializador de clase. No se demuestra que la clase esté activa en el dispositivo conectado.

## Productores y procedencia de registros

El inicializador comienza en `0x60073BF0`; R0 recibe la base global `0x200064C0`, como acredita el llamador fijado en fase 63. Construye las tablas de los objetos y su lista de cuatro punteros. El bucle ejecuta BLX en `0x60073DFC`, lee la tripleta devuelta y la copia con STM.W en `0x60073E00`.

| Objeto SRAM | Método productor original | Registro devuelto SRAM | Offset del registro en el archivo OEM | Selector interno |
|---|---|---|---|---:|
| `0x20009EF0` | `0x600613F4` | `0x200030F4` | `0xFDF5C` | **10** |
| `0x20009E00` | `0x6006262C` | `0x200031F0` | `0xFE058` | 1 |
| `0x20009E84` | `0x60061104` | `0x200030E8` | `0xFDF50` | 2 |
| `0x20009F20` | `0x60061E08` | `0x2000312C` | `0xFDF94` | 4 |

Cada método es un LDR literal que devuelve el puntero original, seguido de BX LR. Las tablas de métodos son, respectivamente, `0x60105A5C`, `0x60105F30`, `0x60105A40` y `0x60105F1C`. La prueba invoca los cuatro métodos originales; no sustituye sus retornos por punteros elegidos por el auditor.

## Array construido y callbacks originales

Los 6.296 bytes de datos inicializados se copian desde el offset OEM `0xFD5A8` a la RAM virtual `0x20002740..0x20003FD8`, usando el mapeo documentado del arranque. Es una copia del archivo firmado a memoria de emulación, **no una lectura de RAM física ni una ejecución del arranque completo**. Su SHA-256 es `85b39fa62734059a14d13a7067330fd1e1cf1570b2ad8b61eb272df00a273806`.

| Destino en el array | Callback original | Instancia antes del init de clase | Descriptor interno | Byte selector del descriptor |
|---|---|---|---|---:|
| `0x2000A274` | **`0x600613FD`** | 0 | `0x20003100` | **10** |
| `0x2000A280` | `0x000021A1` | 0 | `0x200031C4` | 1 |
| `0x2000A28C` | `0x60061249` | 0 | `0x200030A0` | 2 |
| `0x2000A298` | `0x600624F9` | 0 | `0x20003138` | 4 |

Se compara cada tripleta copiada, byte por byte, con su origen en el archivo OEM. El callback `0x21A1` corresponde a código con dirección de ejecución ITCM, no debe interpretarse como una dirección XIP. Ningún callback se ejecuta en esta fase.

El código original también construye los campos del owner `0x2000A2A8`: array `0x2000A274`, método `0x60060D55` y contador byte 4. La presencia de cuatro registros internos sigue siendo compatible con las dos interfaces USB anunciadas en fase 61: son estructuras diferentes.

## Comparación con la tabla de clases original

Tras la construcción del array, una segunda etapa ejecuta el fragmento original `0x60055170..0x60055194` para cada registro. Utiliza los descriptores originales, la tabla ROM `0x60104B74` y las comparaciones originales. Sus cuatro destinos comprobados son:

| Selector del registro original | Método Thumb seleccionado |
|---:|---|
| **10** | **`0x60055321`** |
| 1 | `0x600552F1` |
| 2 | `0x60054C7D` |
| 4 | `0x60054875` |

Para iniciar ese fragmento se inyecta explícitamente `[singleton+4]=owner+4`, junto con sus registros de entrada. **No se han ejecutado la preparación completa del motor USB, sus comprobaciones anteriores, ni los cuatro inicializadores de clase.** El hook se detiene antes de `0x60055194 BLX R3`. Este enlace virtual no equivale a observar activación física.

## Límites de la ejecución del inicializador

La emulación comienza en `0x60073BF0`, con R0/base global y stack sintéticos, y termina antes de `0x60073EF4`. Ejecuta el cuerpo principal, los cuatro productores, las cargas/copia de registros y las escrituras de metadatos. El estado interno del bucle ya no se impone manualmente como en fase 63.

Se mantienen dependencias explícitas: `0x6013CF90` se modela como relleno de bytes limitado a SRAM virtual; `0x600723B4`, `0x600D9B6C` y `0x6013D3A0` son stubs sin efectos que conservan R0. Por ello no se reproduce la inicialización completa de subobjetos, mutexes ni las copias de metadatos de esos helpers. La evidencia registra sus argumentos y los límites aplicados. El resultado se refiere a este flujo bajo esas suposiciones, no a una emulación completa del SoC.

## Reproducción y verificación

```powershell
python -m tools.audit_usb_class_records_phase64 local/bruce.bin --out local/phase64.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_class_records_phase64 -v
```

Requiere `requirements-emulation.txt` y la imagen exacta obtenida por separado del [archivo OEM](https://github.com/StadiaMemories/firmware). El auditor exige el SHA completo, las instrucciones y literales de fase 63, las tablas de clase ROM, cada método productor, los punteros de origen, las tripletas y los bytes selectores. Las pruebas negativas alteran un literal de retorno, un callback original y un selector; todos se rechazan. **729 pruebas locales pasan**, incluidas las pruebas habilitadas contra el OEM original. CI reproduce la evidencia completa sin publicar el firmware.

## Decisión y siguiente paso

La pregunta concreta **«¿incorpora el inicializador la clase 10?» tiene respuesta afirmativa en este flujo OEM modelado**, con registro y callback originales identificados. Se supera el límite histórico de «registro firmado presente pero sin enlace al array». Esto no transforma el callback en un puntero controlado por USB ni demuestra ejecución propia.

La siguiente comprobación es seguir desde el owner construido hasta la llamada real al motor y sus condiciones de éxito, especialmente el método de inicialización de clase 10 y la instalación de su instancia. Después habrá que enlazar los eventos físicos con su invocación. No se han medido esas condiciones en el mando, enviado comandos, escrito flash/eFuses, cambiado de modo ni superado HAB CLOSED.

[Evidencia](../../evidence/usb-class-records-phase64.json) · [Auditor](../../tools/audit_usb_class_records_phase64.py)
