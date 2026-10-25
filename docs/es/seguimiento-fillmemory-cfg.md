# FillMemory — análisis adicional del grafo de llamadas (solo lectura)

**Estado actualizado (PR #27): comprobación sobre el binario original completada satisfactoriamente en CI, sin acceder al mando.** El cargador se obtuvo de un archivo público, se descargó únicamente en un ejecutor efímero y se comprobó su SHA-256 exacto `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`. [Ejecución de verificación original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40233274137). La imagen no se añadió al repositorio ni se guardó como artefacto. Este trabajo amplía [la PR #26](analisis-fillmemory.md).

## Por qué

El comando FillMemory (tag `0x05`) está habilitado en el cargador firmado, con manejador Thumb `0x20003381`. WriteMemory (tag `0x04`) también está habilitado; Execute (tag `0x09`) y Call (tag `0x0A`) están deshabilitados. La PR #24 verificó una política de escritura para **WriteMemory**, pero no para **FillMemory**.

La [referencia NXP](https://mcuxpresso.nxp.com/mcuxsdk/25.09.00/html/middleware/mcu_bootloader/docs/MCU_Bootloader_Reference_Manual/topics/mcu_bootloader_command_api.html) establece que FillMemory recibe dirección, cantidad y patrón, sin fase de datos, y sigue las reglas generales de WriteMemory. Su [interfaz abstracta de memoria](https://mcuxpresso.nxp.com/mcuxsdk/25.09.00/html/middleware/mcu_bootloader/docs/MCU_Bootloader_Reference_Manual/topics/memory_interface.html) separa los métodos `write` y `fill`. **Es documentación genérica, no prueba de cómo funciona el cargador restringido Stadia.**

## Qué aporta el nuevo auditor

`tools/audit_fillmemory_cfg.py`:
- Rechaza imágenes que no coincidan en tamaño y SHA-256 con el cargador privado conocido y comprueba las cuatro entradas de despacho relevantes.
- Empieza en `0x20003380`; sigue las **ramas directas** y ambos lados de las ramas condicionales, dentro de ventanas por función.
- Sigue llamadas `BL/BLX` directas hasta una profundidad y presupuesto configurables, registrando las llamadas observadas.
- Señala explícitamente llamadas/saltos indirectos, instrucciones sin decodificar, ramas fuera de ventana, estado `IT` sin modelar y límites de profundidad.
- Marca la aparición de llamadas directas al verificador `0x200039A8` y al backend `0x20003B7C` previamente identificados para WriteMemory.

**Limitación esencial:** se trata de una **sobreaproximación parcial** del flujo de control, no una ejecución simbólica ni un análisis de datos, parámetros, rutas dinámicas o semántica de validación. Una llamada encontrada puede no ejecutarse para entradas reales. La ausencia de llamadas en la muestra limitada **no demuestra ausencia de filtrado, vulnerabilidad ni bypass**. Las ventanas no equivalen a límites de función y no se reconstruyen todas las operaciones por punteros.

## Ejecución local

```sh
python -m unittest tests.test_fillmemory_cfg -v
python tools/audit_fillmemory_cfg.py local/restricted_ivt_flashloader.bin --out local/fillmemory-cfg.json
```

No publicar el fichero original ni el resultado local sin revisión de privacidad y procedencia. La CI ejecuta únicamente pruebas sintéticas, nunca interacciona con el mando.

## Criterio para continuar

1. **Ejecutar contra la copia privada original** y conservar un informe reproducible.
2. Revisar los saltos indirectos y las funciones pertinentes, siguiendo los **valores** de dirección, longitud y patrón hasta la política de memoria o su equivalente; no quedarse en coincidencias de direcciones de funciones.
3. Determinar si las ramas de FillMemory verifican los rangos de destino, overflow y alineación para cada recorrido. Comparar con las protecciones de WriteMemory.
4. Mantener sin demostrar la ejecución propia y la recuperación mientras no haya evidencia específica de ambas. **HAB CLOSED** continúa activo.

**No se han enviado paquetes USB, escrito RAM/flash, activado Execute/Call ni cambiado eFuses.**


## Resultado confirmado sobre la implementación original

El auditor nuevo `tools/audit_fillmemory_verified.py` verificó los siguientes
punteros e instrucciones directamente en la imagen auténtica:

- `0x20003380`: manejador FillMemory, con `BLX R3` que llama al método
  `fill` de la interfaz global de memoria.
- El global copiado al inicio `0x202081F4` apunta en su estado inicial a la
  interfaz `0x20015E8C`. La entrada `+0x0C` contiene `0x20003C87`
  (función Thumb `0x20003C86`).
- `0x20003C94`: pasa código de operación **0**; `0x20003C96`
  llama al verificador de rangos compartido `0x200039A8`.
- `0x20003CA0` y `0x20003CAC`: comprobaciones adicionales en
  `0x20003B30` y `0x200039F4`; `0x20003CBE`: salto indirecto
  a la implementación específica de memoria.
- `WriteMemory` utiliza **operación 2** sobre el mismo `0x200039A8`.

Por el tipo de operación, la política inicial consultada para FillMemory es
**una tabla de cinco rangos**, distinta de la de cuatro rangos de WriteMemory:

| FillMemory (op 0) | Fin inclusivo |
|---|---|
| `0x00002000` | `0x00002003` |
| `0x400F8030` | `0x400F803B` |
| `0x402A8014` | `0x402A8017` |
| `0x402A8080` | `0x402A8083` |
| `0x402A80A0` | `0x402A80BF` |

Las entradas de habilitación de Execute (`0x200159E0`) y Call
(`0x200159EC`) **quedan fuera de todos los rangos**. Para escrituras
de longitud positiva sin desbordamiento aritmético, la ruta directa
de FillMemory no puede modificar estos dos campos por su política inicial.

**Incertidumbre residual importante:** en `0x200039BC..0x200039C2`
se calcula `fin = inicio + longitud - 1` con aritmética ARM de
32 bits. Un valor anormal que envuelva la suma puede invalidar el
razonamiento de intervalos no envolventes. Las comprobaciones posteriores
de región y mapa en `0x20003B30` y `0x200039F4`, así como el
backend indirecto de memoria, deben verificarse antes de atribuir efecto
a tal caso. **No se ha demostrado una escritura fuera de límites,
control de flujo, explotación, ejecución propia ni recuperación.**

## Herramientas y validación de imagen real

```sh
python -m tools.audit_fillmemory_verified local/restricted_ivt_flashloader.bin --out local/fillmemory-verified.json
python -m tools.audit_fillmemory_cfg local/restricted_ivt_flashloader.bin --out local/fillmemory-cfg.json
python -m unittest tests.test_fillmemory_cfg tests.test_fillmemory_verified -v
```

La ejecución aislada de CI descarga la copia del
[archivo público StadiaMemories/firmware](https://github.com/StadiaMemories/firmware)
y comprueba exactamente su SHA-256 antes de ejecutar los auditores.
No envía ninguna petición USB o HID. La ejecución
[40233274137](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40233274137)
ha concluido correctamente.
