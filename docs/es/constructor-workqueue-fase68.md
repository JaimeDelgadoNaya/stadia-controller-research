# Fase 68 — Constructor original de Work Queue y campos auxiliares

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 67](llamada-workqueue-fase67.md).

## Resultado principal

Se ha identificado y ejecutado el constructor original **`0x600926D0`**, que establece los campos del objeto **`0x2002014C`** usados por la llamada de fase 67. El puntero auxiliar y su palabra de tamaño ya no son fixtures elegidos por el auditor: los escriben las instrucciones OEM.

El constructor deja el handle a cero y configura una estructura en **`objeto+0x12C = 0x20020278`**, con palabra de tamaño **`0x200`** y puntero de buffer **`0x2002034C`**. Usar esos campos originales permite recorrer la ruta de creación de fase 67, cuyo retorno sigue modelado. No se demuestra que una tarea real se haya creado ni que el constructor se ejecutara en el mando conectado.

## Enlace con la tabla de inicializadores

La entrada del archivo **`0xFD59C`** contiene el puntero Thumb **`0x600926D1`**. Está en el índice **43**, comenzando en cero, de las **45 entradas** del intervalo firmado `0x6013D4F0..0x6013D5A4`.

Se reutiliza la comprobación de instrucciones y límites del walker **`0x600CDB74`** de fase 43. Su carga y BLX recorren ese intervalo. Esto acredita la pertenencia del constructor a la tabla que usa el walker original; **no prueba que todo el arranque anterior complete la iteración 43 en hardware**.

## Escrituras originales verificadas

| Campo | Dirección | Valor tras el constructor virtual | Instrucción de procedencia |
|---|---|---|---|
| Handle `objeto+0x58` | `0x200201A4` | **0** | STRD en `0x600926F4` |
| Puntero auxiliar `objeto+0x5C` | `0x200201A8` | **`0x20020278`** | STR en `0x6009271E` |
| Auxiliar `+0xCC` | `0x20020344` | **`0x2002034C`** | STR.W en `0x6009270C` |
| Auxiliar `+0xD0` | `0x20020348` | **`0x200`** | STR.W en `0x60092716` |

El desplazamiento de la palabra de tamaño por dos bits produce `0x800`, justo el umbral aceptado por la guarda original de fase 67. Los nombres de buffer/estructura describen su uso en esa ruta; no prueban su uso por un planificador en ejecución.

Se ejecutan dos escenarios: estado virtual inicial ordinario y campos handle/auxiliar sembrados con `A5A5A5A5/5A5A5A5A`. En ambos, las escrituras originales producen los mismos cuatro campos. El segundo caso es un control de sobrescritura; no se presenta como un estado físico alcanzable.

## Dependencias del constructor

El cuerpo `0x600926D0` y los helpers originales **`0x601017FC`** y **`0x600C9DE4`** se ejecutan. El helper más profundo **`0x6013D3D0`** conserva un modelo sin efectos que devuelve R0 sin cambios; su inicialización de kernel no se reproduce.

La prueba se detiene al entrar en el wrapper final `0x60101C48`, después de construir los campos y restaurar el frame, sin ejecutar ese registro final. Por tanto, los resultados se refieren al flujo con los helpers modelados y no a una reproducción completa del sistema o a la garantía de que los auxiliares reales siempre retornan.

## Continuación con los campos OEM

La herramienta de fase 67 incorpora una opción interna para **preservar los campos recibidos**, en lugar de sustituirlos por fixtures. Su comportamiento anterior por defecto conserva la misma evidencia.

En esta fase se entrega la RAM virtual producida por el constructor y se ejecuta la llamada de modo y `0x6009267C`. El handle empieza en cero y el puntero/tamaño originales superan sus guardas. La rutina **`0x600CA1F8` sigue siendo un stub que devuelve un handle opaco**; ese retorno lo almacena la instrucción original del wrapper, y la función de modo retorna al llamador.

Tras ese retorno se inicia la transición y driver originales con MMIO virtual 8, como en fase 66, hasta enlazar la instancia de clase 10 **`0x200040E0`**. El join entre etapas, los modelos de registro/sincronización y el helper de transición siguen explícitos. No se ejecutan la publicación final del modo, callbacks ni las otras clases.

## Reproducción y validación

```powershell
python -m tools.audit_workqueue_constructor_phase68 local/bruce.bin --out local/phase68.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_workqueue_constructor_phase68 -v
```

Requiere `requirements-emulation.txt` y la imagen exacta del [archivo OEM](https://github.com/StadiaMemories/firmware), obtenida por separado. Se exige SHA completo, límites del walker, entrada 43, instrucciones de escritura y resultados. Las pruebas negativas alteran el puntero de tabla, la escritura auxiliar y el tamaño. **746 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce y compara la evidencia completa. No se publican el binario ni un snapshot de RAM.

## Qué queda pendiente

Se sustituye la estructura auxiliar sintética de fase 67 por **productores OEM identificados y ejecutados**. La procedencia del handle queda acotada al retorno de `0x600CA1F8`, cuyo cuerpo y efectos del planificador todavía no se ejecutan en esta cadena. Ese es el siguiente punto, junto con el helper de kernel `0x6013D3D0` y la continuidad real del arranque.

No se han medido campos instalados, creado tareas reales, enviado comandos al mando ni modificado firmware/eFuses. La activación física de clase 10, ejecución propia y elusión HAB siguen sin demostrarse.

[Evidencia](../../evidence/usb-workqueue-constructor-phase68.json) · [Auditor](../../tools/audit_workqueue_constructor_phase68.py)
