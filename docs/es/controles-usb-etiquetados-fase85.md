# Fase 85 — Controles USB identificados con acciones confirmadas

27 de octubre de 2026. El propietario manejó el mando conectado por USB. Se pidió una sola acción por ventana y, después de cada lectura, confirmó expresamente que había accionado únicamente el control indicado. Las capturas contienen informes HID agregados; no incluyen rutas, seriales ni tiempos u orden por informe.

## Mapa físico observado

| Control confirmado | Campo USB observado |
|---|---|
| A / B / X / Y | Usos de botón **1 / 2 / 4 / 5** |
| Cruceta arriba / derecha / abajo / izquierda | Hat **0 / 2 / 4 / 6**; soltado **8** |
| Gatillo izquierdo | Analógico página 2 uso **0xC5**, de 0 a 255; botón digital **20** |
| Gatillo derecho | Analógico página 2 uso **0xC4**, de 0 a 255; botón digital **19** |

Cada botón frontal y cada dirección cardinal produjo dos estados distintos, uno activo y otro liberado, mientras los ejes y otros botones permanecieron constantes. Para cada gatillo se observaron valores intermedios y ambos extremos, sin cambios en los demás ejes. El izquierdo produjo 346 informes y el derecho 345; estas cifras no son números de pulsaciones.

**Hallazgo relevante para las fases 83–84:** los usos USB 20 y 19, que aún carecían de una etiqueta física, corresponden respectivamente a los gatillos izquierdo y derecho en esta sesión. Son indicadores digitales adicionales a los valores analógicos. En los valores muestreados, ambos indicadores son compatibles con un límite candidato de 64: el izquierdo estuvo desactivado entre 0–63 y activado entre 64–255; el derecho, desactivado entre 0–63 y activado entre 65–255. **No se obtuvo el valor 64 para el derecho** y los informes agregados no conservan orden; no se ha demostrado un umbral exacto universal ni ausencia de histéresis.

Las posiciones de A/B/X/Y y de los valores analógicos de ambos gatillos coinciden con las etiquetas y posiciones que utiliza el código del puente BLE fijado. El puente convierte los valores analógicos de gatillo y la prueba host anterior mostró que no incluye esos bits digitales en sus 13 banderas examinadas ni en su salida Xbox. La observación USB explica su función aquí, pero todavía falta una medición BLE para afirmar que sus posiciones y semántica sean las mismas por radio o determinar el efecto real en el puente.

No se probaron diagonales, sticks, LB/RB, vibración ni salida de consola. No hubo informes HID de salida, cambios de modo o escritura de firmware/eFuses. Las acciones confirmadas y sus informes se guardan en [capturas agregadas](../../evidence/usb-labeled-controls-phase85.json); el [mapa derivado](../../evidence/usb-control-map-phase85.json) se reproduce offline con:

```powershell
python -m tools.analyze_labeled_controls_phase85 evidence/usb-labeled-controls-phase85.json evidence/stadia-hid-report-contract.json evidence/usb-ble-layout-comparison-phase83.json --out local/control-map85.json
python -m unittest tests.test_labeled_controls_phase85 -v
```

El analizador rechaza muestras sin confirmación, datos contaminados por otros controles, recuentos inconsistentes o descriptor incorrecto. CI reproduce el análisis de la evidencia guardada; no repite la medición física.
