# FillMemory — análisis adicional del grafo de llamadas (solo lectura)

**Estado:** comprobación reproducible añadida; **el binario restringido de Google no está disponible en este entorno**, por lo que **no se afirma haber ejecutado este auditor sobre el original**. Este trabajo amplía [la PR #26](analisis-fillmemory.md) y mantiene la prohibición de escribir o enviar comandos al dispositivo.

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
