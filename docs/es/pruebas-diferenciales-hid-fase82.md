# Fase 82 — Pruebas diferenciales del decodificador HID

27 de octubre de 2026. Continuación exclusivamente offline: no se abrió el mando ni se solicitaron acciones físicas.

## Resultados

Se contrastó el decodificador directo de fase 81 con una referencia que extrae los campos usando el descriptor registrado y el extractor genérico de fase 80. No hay discrepancias en **39.424 vectores sintéticos**:

| Familia | Casos |
|---|---:|
| Todos los subconjuntos de los 15 botones, incluidos simultáneos | 32.768 |
| Cada uno de los 10 bytes de payload con los 256 valores posibles, manteniendo los demás en un vector neutro sintético | 2.560 |
| Payloads mixtos pseudoaleatorios reproducibles, semilla 82 | 4.096 |

El barrido de bytes incluye hat, ejes, valores de página 2, Consumer y padding. Se comparan todos los campos devueltos, incluidos diagnósticos y estados nulos. Esto agota las combinaciones de botones, **no** el espacio completo de 80 bits del payload ni sus posibles interacciones.

Se verificó además el rechazo de los **255 IDs distintos de 3**, las **64 longitudes incorrectas entre 0 y 64** y **1.504 alteraciones individuales de un bit del descriptor**. Estas últimas validan la guarda por hash, no el comportamiento de dispositivos con otros descriptores.

Dos controles negativos introducen deliberadamente errores en el decodificador bajo prueba: intercambio de dos usos de botón y supresión del diagnóstico de padding. El auditor detecta ambos. El flujo de vectores tiene un SHA-256 reproducible para identificar el corpus exacto. La referencia comparte el parser/extractor genérico anterior; no constituye una validación independiente de ese parser ni del estándar HID completo.

## Corrección encontrada

El replay de fase 81 validaba los conteos de cada fila, pero comparaba el total con igualdad numérica. Python considera `True == 1` y `1.0 == 1`, por lo que esos totales se aceptaban en ciertos documentos. Ahora `report_count` debe ser un entero no negativo y rechaza explícitamente booleanos, flotantes, negativos, cadenas y valores nulos. No cambia el resultado de las capturas válidas publicadas.

## Reproducción

```powershell
python -m tools.audit_hid_differential_phase82 evidence/stadia-hid-report-contract.json --out local/differential82.json
python -m unittest tests.test_hid_differential_phase82 -v
```

[Evidencia](../../evidence/usb-hid-differential-phase82.json). El trabajo aumenta la confianza en el procesamiento de entrada para un posible puente. No identifica físicamente A/B, sticks o gatillos, no mide latencia/polling y no prueba salida hacia consola, autenticación, compatibilidad Xbox/Switch, alcance de Work Queue ni firmware propio.
