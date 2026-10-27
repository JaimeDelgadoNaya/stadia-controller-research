# Fase 84 — Pruebas host del puente BLE original

27 de octubre de 2026. Se compiló para el ordenador el `bridge.c` original del proyecto BLE fijado en fase 83, con Zig/Clang 0.13.0 y colas FreeRTOS sustituidas por stubs de compilación. Se ejecutaron directamente las funciones originales de conversión y parser mediante un wrapper de pruebas. El código GPL permanece en su checkout separado: no se incorpora ni modifica. Se verificaron el commit, los hashes fijados del proyecto y la identidad de las cabeceras frente al objeto Git del commit.

## Qué ocurre con los bits observados

Se probó individualmente cada bit de los bytes 1, 2 y 9 de un payload sintético de 10 bytes. Además, se reutilizaron los 1.399 payloads USB distintos de fase 80 **como entradas BLE hipotéticas**, alternando por separado cinco bits por cada payload: **6.995 comparaciones emparejadas** (8.790 si se ponderan por la frecuencia de los informes). Todas conservaron tanto los 20 bytes de salida como las 13 banderas semánticas observadas, para esos cinco bits.

| Bit de entrada hipotética | Correspondencia USB declarada | Resultado de las funciones C originales probadas |
|---|---|---|
| Byte 1, bits 2 y 3 | Usos de botón USB 20 y 19 | No cambian la salida Xbox ni las 13 banderas inspeccionadas |
| Byte 9, bits 0–2 | Usos Consumer USB | No cambian la salida Xbox ni las 13 banderas inspeccionadas |
| Byte 1, bit 0 | Uso USB 18; upstream lo llama Capture | Cambia la bandera `capture`, no los bytes Xbox |
| Byte 1, bit 1 | Uso USB 17; upstream lo llama Assistant | Cambia la bandera `assistant`, no los bytes Xbox |

El parser también conserva una copia de los bytes originales: «sin cambio» se refiere únicamente a las 13 banderas inspeccionadas y a la salida de 20 bytes, no a toda la estructura. El código del receptor pasa las banderas Assistant/Capture a un subsistema de acciones configurables; esta prueba no lo ejecuta. Los demás estados, colas, temporización, comunicaciones y reconexiones tampoco se han ejecutado.

Los resultados sobre USB como entrada hipotética **no demuestran que BLE use la misma disposición**, ni que esos bits correspondan a los mismos controles físicos. Por tanto, no se demuestra pérdida real de controles. La diferencia justifica una futura captura BLE con acciones etiquetadas antes de modificar el puente o atribuirle un defecto.

## Reproducción

```powershell
python -m pip install ziglang==0.13.0
python tools/prepare_external_bridge.py local/stadia-dongle-esp --verify-only
python -m tools.audit_bridge_host_phase84 local/stadia-dongle-esp evidence/usb-live-hid-input-phase80.json --library local/bridge84.dll --out local/bridge84.json
```

Para ejecutar también la reproducción desde unittest, establecer `STADIA_BRIDGE_CHECKOUT` al checkout y `STADIA_BRIDGE_LIBRARY` a una ruta absoluta de salida para la biblioteca. CI realiza esta prueba en Linux con el checkout fijado; el experimento local original se realizó en Windows. [Evidencia](../../evidence/usb-bridge-host-tests-phase84.json).

No se ha compilado el firmware ESP32, emparejado el mando, ejecutado BLE o validado una consola. No hubo lecturas nuevas del dispositivo ni escrituras de firmware/eFuse.
