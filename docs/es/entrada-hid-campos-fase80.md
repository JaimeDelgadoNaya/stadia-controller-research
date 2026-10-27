# Fase 80 — Entrada HID física y campos observados

27 de octubre de 2026. Tras la ventana vacía de fase 79, se solicitó en el chat pulsar A/B, mover sticks y apretar gatillos durante una nueva lectura de 30 segundos. Se recibieron **1.758 informes**, con **1.399 contenidos distintos**. Todos llevan **ID 3 y 11 bytes**, confirmando dinámicamente ese contrato en esta ventana.

Las acciones se solicitaron, pero no se confirmó su realización ni se etiquetó cada muestra. Por tanto, los resultados acreditan variación en los campos declarados, sin asignar todavía A/B o izquierda/derecha a bits concretos. La lectura vacía anterior no era prueba de fallo; esta medición tampoco establece su causa.

## Mapa derivado del descriptor y contraste físico

Offsets de bits relativos al payload, excluyendo el byte ID:

| Campo del descriptor | Offset | Observación |
|---|---:|---|
| Hat, página 1 uso 0x39 | 0 | Siempre 8; rango lógico 0–7 y flag Null State 0x40 |
| 15 botones, página 9 | 8 | Ocho elementos variaron entre 0 y 1 |
| X/Y, página 1 usos 0x30/0x31 | 24 | Ambos alcanzaron 1 y 255; 232 valores distintos por eje |
| Z/Rz, página 1 usos 0x32/0x35 | 40 | Ambos alcanzaron 1 y 255; 213 y 208 valores distintos |
| Página 2 usos 0xC5/0xC4 | 56 | Ambos alcanzaron 0 y 255; 142 y 148 valores distintos |
| Página 0x0C usos 0xE9/0xEA/0xCD | 72 | Siempre cero |

El valor 8 del hat queda fuera del rango lógico, pero el descriptor permite un estado nulo: no se clasifica como error. Los campos de padding constantes permanecieron a cero. El analizador conserva usos numéricos y no interpreta rangos de usos ni colecciones más allá del decoder previo.

Los agregados no conservan orden ni tiempos por muestra: 1.758/30 es un promedio de entrega de esta ventana, **no prueba de frecuencia de polling**. Esta observación se hace mediante la pila HID de Windows, no mediante captura de paquetes USB. No observa endpoints bulk, Work Queue, callbacks ni firmware sin firma. No se enviaron salidas, features ni cambios de modo, ni se escribió firmware/eFuses.

## Reproducir el análisis offline

```powershell
python -m tools.analyze_hid_input_phase80 evidence/usb-live-hid-input-phase80.json evidence/stadia-hid-report-contract.json --out local/fields80.json
python -m unittest tests.test_hid_fields_phase80 -v
```

La captura usó `capture(30)` de la herramienta de fase 79; la evidencia distingue acciones solicitadas de acciones verificadas. Para repetirla, instalar `hidapi==0.14.0.post4` y ejecutar la herramienta de fase 79 con `--seconds 30`; su campo de acciones por defecto corresponde a una observación sin acciones solicitadas y debe documentarse si cambia el protocolo. El análisis offline no requiere hidapi ni mando. CI reproduce el análisis de los agregados publicados, no la medición física.

[Captura agregada](../../evidence/usb-live-hid-input-phase80.json) · [Campos observados](../../evidence/usb-hid-field-observations-phase80.json).

Siguiente frontera útil: capturas separadas con una acción etiquetada cada vez para fijar el mapeo físico de botones y gatillos; el hat necesita una prueba explícita de cruceta. La ruta de entrada HID ya tiene evidencia física suficiente para priorizar un puente externo sin depender de la hipótesis de ejecución propia.
