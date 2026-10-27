# Fase 81 — Decodificador HID offline para preparar el puente

27 de octubre de 2026. Se continúa offline por indicación del usuario. Las dos ventanas iniciales solicitadas (reposo y A, cinco segundos cada una) no recibieron informes y no se confirmaron acciones; no se usan para asignar controles. No se realizaron más lecturas físicas tras esa indicación.

El nuevo decodificador transforma los informes físicos ya agregados en fase 80 en estado estructurado. Exige el hash SHA-256 del descriptor registrado y el contrato ID 3 / 11 bytes. Conserva nombres de ejes HID, usos de botones y valores sin normalización ni asignación física especulativa.

## Hallazgo útil: el orden de botones no es consecutivo

Los bits 0–14 del bloque de botones corresponden, en este orden, a los usos HID:

```text
18, 17, 20, 19, 13, 12, 11, 15, 14, 8, 7, 5, 4, 2, 1
```

Suponer bit 0 = botón 1 produciría una traducción incorrecta. El decodificador deriva este contrato del descriptor, y las pruebas lo contrastan con la extracción genérica de campos para los **1.399 informes distintos** registrados. Los vectores one-hot prueban además los quince bits, incluidos los que no variaron en la captura.

En el replay de **1.758 informes**, los usos activos fueron 20 (252 informes), 19 (222), 15 (1), 14 (15), 8 (20), 7 (8), 2 (9) y 1 (43). Estos números son conteos de informes con el bit activo, **no pulsaciones ni duraciones**; puede haber botones simultáneos. No se atribuyen todavía nombres físicos A/B.

El hat vale 8 en todos los informes y se representa con dirección `null`, según el flag Null State y rango 0–7. Los códigos 8–15 se conservan en `hat_raw` y quedan fuera de las ocho direcciones; no se inventa orientación cardinal. X/Y/Z/Rz mantienen sus bytes (rango declarado 1–255); los usos de página 2 0xC5/0xC4 mantienen rango 0–255. Los valores fuera de rango y padding no nulo se señalan explícitamente en vez de descartarse. En esta captura no aparecen esos indicadores. Los tres usos Consumer permanecieron inactivos.

## Uso y verificación

```powershell
python -m tools.decode_hid_input_phase81 evidence/usb-live-hid-input-phase80.json evidence/stadia-hid-report-contract.json --out local/replay81.json
python -m unittest tests.test_hid_decoder_phase81 -v
```

La función `decode_report(raw, descriptor)` devuelve hat, lista de usos de botones, ejes, valores de página 2, usos Consumer y diagnósticos. El replay no requiere mando ni hidapi. Las pruebas cubren extracción independiente, bits individuales, límites analógicos, estados nulos, padding y rechazo de formato/descriptor/conteos incorrectos.

[Evidencia reproducible](../../evidence/usb-hid-decoder-replay-phase81.json). Esto prepara la parte de entrada de un posible puente externo. No implementa emulación de salida, autenticación de consola, XInput, compatibilidad Xbox/Switch, enlace con Work Queue ni ejecución de firmware propio. Siguen pendientes asignaciones físicas etiquetadas y validación del destino del puente.
