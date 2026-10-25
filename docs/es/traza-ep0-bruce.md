# Bruce — ruta USB SETUP hasta despacho de callback de endpoint

**Fase de investigación #33 · 25 de octubre de 2026 · exclusivamente offline.**

## Muestra y alcance

El análisis requiere la imagen OEM Bruce original firmada (1.050.984 bytes), SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Es una **imagen de actualización**, no una lectura completa de la flash del mando. Las instrucciones, vectores, punteros de trampolines y anclas del despachador se contrastan contra esta imagen exacta; no se envían paquetes USB ni se escribe en el mando.

La meta es reconstruir `SETUP USB → interrupción → recepción → callback EP0` y establecer dónde termina la evidencia verificable, antes de asumir que los valores de consulta de versión/batería constituyen puertas de ejecución.

## Cadena de código comprobada

| Etapa | Evidencia estática sobre la imagen |
|---|---|
| USB OTG1, IRQ 113 | Tabla de vectores de la imagen en offset `0x204` → puntero Thumb `0x600610D1` |
| Wrapper de interrupción | `0x600610D0` comprueba un estado global y, cuando vale 2, salta a `0x6013D1F8` |
| Trampolín XIP → ITCM | `0x6013D1F8` contiene `LDR.W PC,[PC]`, literal `0x00001111`; destino ITCM `0x00001110` |
| Manejador USB reubicado | `0x00001110` lee los registros USB `+0x144`/`+0x148`, y posteriormente `ENDPTSETUPSTAT` `+0x1AC` |
| Recepción de SETUP | `0x000011C6` lee `ENDPTSETUPSTAT`; el bloque `0x11D0..0x1258` procesa los bits de endpoint y copia la información SETUP mediante el mecanismo de tripwire |
| Puerta a la capa de eventos | `0x00001258: BL 0x0000BA68`, trampolín Thumb de ITCM cuyo literal apunta a `0x600D0FB7` |
| Despachador XIP | `0x600D0FB6` clasifica los eventos de endpoint, obtiene el índice del callback de una tabla RAM y llama a `BLX R5` en `0x600D104E` |

### Registro y selección del callback

El despachador no usa los valores `0x81/0x83/0x84` para seleccionar directamente una función. En cambio, decodifica un byte de **evento de endpoint** en `[R1,#8]`:

- `0x600D1010`: extrae el número `endpoint & 0x0f`, con límite 7.
- `0x600D1018..0x600D101A`: combina el número con el bit de dirección, calculando `2*(endpoint&0x0f)+((endpoint>>7)&1)`.
- `0x600D1020`: calcula la entrada de tabla con un **paso de 12 bytes**.
- `0x600D104A`: carga la pareja de función y contexto de la entrada.
- `0x600D104E`: ejecuta la llamada indirecta **`BLX R5`**, condicional a que la entrada exista y el evento sea aceptado.

La semántica de esta ruta se ha anclado a instrucciones específicas con verificaciones de Capstone, no a una coincidencia de palabras. **Todavía no se ha identificado el valor concreto cargado en la entrada EP0 en una sesión real**, ni qué función se registra allí durante la inicialización.

### Solicitudes host `0x81/0x83/0x84`

El JavaScript OEM archivado emplea peticiones USB de clase/interfaz `0x81` (leer versión), `0x83` (iniciar consulta de batería) y `0x84` (leer batería). No se deben confundir con etiquetas de *payload* vistas en código Bruce.

El auditor `tools/audit_bruce_ep0_setup_provenance.py` confirma que las ocho comparaciones literales estudiadas en la fase anterior **no leen directamente** `bRequest` del desplazamiento `+1` del SETUP. En un barrido lineal más amplio aparecieron **49** parejas de cargas byte `+0/+1`, pero **ninguna** con las constantes de solicitud relevantes comparadas cerca. Ese barrido puede incluir datos interpretados como código y omite tablas, valores transformados, saltos indirectos y parte del código reubicado; no demuestra que falte un receptor.

## Límites de evidencia

- **Sí demostrado estáticamente:** desde el vector USB OTG1 y el estado de modo 2 existe una cadena condicional de instrucciones firmadas hasta el mecanismo de recepción de SETUP y el despacho de callback de endpoint mediante `BLX`.
- **Sin demostrar:** `SCB→VTOR` efectiva en el mando, valor de selección de modo, contenido real de la tabla de callbacks, callback específico de **EP0**, alcance de un `bRequest` concreto y efectos de memoria de la función seleccionada.
- **Sin conseguir:** ejecución de código propio, bypass HAB CLOSED, modificación persistente recuperable, compatibilidad directa con Xbox o Switch 2.
- **Sin riesgos sobre el mando:** no hay USB enviado, escrituras de RAM/flash, eFuses modificados ni recuperación experimental.

## Criterio de la siguiente investigación

Seguir **las escrituras del inicializador en los slots 0/1 del objeto de callbacks**, verificar la función de EP0 que llega por el `BLX`, y reconstruir desde ese receptor el uso del campo `SETUP.bRequest` y sus límites de longitud. Las lecturas estáticas del código firmado no equivalen a una puerta de ejecución arbitraria.

## Reproducción (sin hardware)

```bash
python -m unittest tests.test_bruce_ep0_setup_provenance tests.test_bruce_usb_irq_vector -v
python -m tools.audit_bruce_ep0_setup_provenance local/bruce_pvt_a_prod_signed.bin --compact
python -m tools.audit_bruce_usb_irq_vector local/bruce_pvt_a_prod_signed.bin --out local/ep0-irq.json
```

El workflow `.github/workflows/signed-app-host-boundary.yml` verifica SHA-256, ejecuta ambos auditores con una copia temporal de la imagen pública y la elimina sin guardar binarios como artefactos.
