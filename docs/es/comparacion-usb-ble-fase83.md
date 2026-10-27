# Fase 83 — Comparación de posiciones USB y puente BLE

27 de octubre de 2026. Continuación offline con la captura USB de fase 80 y el código del puente BLE ya preparado en fase 32. El checkout GPL-3.0 permanece independiente y fijado al [commit d8392de8](https://github.com/danzig666/stadia-dongle-esp/tree/d8392de8f838e12cf16c985b9beb8080c7acd970); el analizador exige el SHA-256 registrado de `main/bridge.c` y del descriptor USB. No se copian fuentes del puente al proyecto.

## Posiciones coincidentes, etiquetas aún hipotéticas

El parser del puente upstream asigna etiquetas de **13 botones y seis valores analógicos BLE**. Si se comparan sus offsets con los del payload USB, excluyendo el byte de ID 3, todos coinciden con campos declarados por el descriptor USB. Esta coincidencia es estructural: **no demuestra que el mando tenga el mismo significado físico en USB y BLE** ni confirma las etiquetas del upstream para nuestro mando.

| Etiqueta BLE en upstream | Byte y bit del payload | Uso de botón USB | Informes USB con bit activo |
|---|---|---:|---:|
| A | 2, bit 6 | 1 | 43 |
| B | 2, bit 5 | 2 | 9 |
| LB | 2, bit 2 | 7 | 8 |
| RB | 2, bit 1 | 8 | 20 |
| LS | 2, bit 0 | 14 | 15 |
| RS | 1, bit 7 | 15 | 1 |

Los conteos son informes, no pulsaciones. El archivo de [evidencia](../../evidence/usb-ble-layout-comparison-phase83.json) incluye también las demás etiquetas. Los usos USB **19 y 20** no tienen etiqueta entre las 13 asignaciones extraídas del parser BLE; en la captura sus bits aparecen activos en 222 y 252 informes, respectivamente. No sabemos si tienen igual significado o siquiera se transmiten igual por BLE; esto no demuestra un fallo físico del puente.

En los campos analógicos, las posiciones declaradas por el upstream para LX/LY/RX/RY coinciden con usos USB X/Y/Z/Rz; LT/RT coinciden con los usos de página 2 `0xC5/0xC4`. Igual posición no demuestra izquierda/derecha ni calibración sin una prueba etiquetada.

**Diferencia del último byte:** el comentario upstream describe el byte 9 BLE como padding, mientras el descriptor USB define en el byte 9 del payload tres bits Consumer y cinco constantes. Los tres bits Consumer permanecieron a cero en nuestra captura; con estos datos no se puede establecer si las dos rutas transportan los mismos controles multimedia. Tampoco se han comprobado el transporte BLE real ni la traducción de salida.

## Reproducir

```powershell
python tools/prepare_external_bridge.py local/stadia-dongle-esp
python -m tools.compare_bridge_layout_phase83 local/stadia-dongle-esp/main/bridge.c evidence/stadia-hid-report-contract.json evidence/usb-live-hid-input-phase80.json --out local/layout83.json
$env:STADIA_BRIDGE_SOURCE = (Resolve-Path local/stadia-dongle-esp/main/bridge.c).Path
python -m unittest tests.test_bridge_layout_phase83 -v
```

Si el checkout ya existe, usar `--verify-only` en la primera orden. Las pruebas generales funcionan sin el checkout; la reproducción de evidencia se omite si falta `STADIA_BRIDGE_SOURCE`. La comparación de posiciones no compila ni ejecuta el puente, accede al mando ni demuestra compatibilidad de consola. Próxima prueba discriminante: acciones etiquetadas por control en USB y, cuando sea posible, captura BLE separada con el mismo protocolo.
