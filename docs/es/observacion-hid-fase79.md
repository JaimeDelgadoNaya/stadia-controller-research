# Fase 79 — Observación física acotada de entrada HID

27 de octubre de 2026. Tras el criterio de corte de fase 78, se vuelve a una observación del mando conectado, sin seguir extendiendo la coincidencia del inicializador Work Queue.

El mando aparece en Windows con VID 18D1 / PID 9400 y una colección HID Game Pad (página 1, uso 5). Se abrió esa colección con hidapi 0.14.0.post4 y se realizaron lecturas de entrada durante 10,015 segundos. **Resultado: cero informes entregados por Windows durante esa ventana.** No se solicitaron pulsaciones ni se etiquetaron acciones físicas.

La ausencia de informes no demuestra fallo, ausencia de tráfico USB, ni incompatibilidad del mando. Tampoco permite distinguir inactividad, comportamiento de publicación, modo del dispositivo u otras causas. El contrato previo de ID 3 y longitud 11 bytes sigue siendo evidencia de descriptor; esta captura vacía no lo valida dinámicamente. No se observan los endpoints bulk de la interfaz de proveedor.

La herramienta no invoca escrituras HID, informes de salida, features ni comandos de cambio de modo. Abrir y leer HID utiliza la pila de Windows; **no es una captura pasiva de paquetes del bus**. No se instalaron controladores ni se escribieron firmware/eFuses. Los identificadores de instancia, rutas y números de serie no se guardan. No hay prueba nueva de enlace USB→Work Queue, callback o ejecución propia.

## Reproducción

En Windows con el mando conectado y una sola colección coincidente:

```powershell
python -m pip install hidapi==0.14.0.post4
python -m tools.capture_hid_input_phase79 --seconds 10 --out local/hid-observation.json
python -m unittest tests.test_live_hid_phase79 -v
```

La duración máxima es 30 segundos. La herramienta agrega los bytes distintos y sus frecuencias, sin conservar orden ni tiempos por informe. Los tests comprueban el procesamiento y la evidencia guardada; CI no reproduce una medición física.

[Evidencia](../../evidence/usb-live-hid-input-phase79.json). Siguiente experimento discriminante: una ventana de lectura con pulsaciones deliberadas y etiquetadas por el usuario; si sigue vacía, contrastar con una captura USB de bus antes de atribuirlo al firmware. No hay USBPcapCMD ni tshark en PATH y no se encontraron sus carpetas habituales en esta sesión; eso no excluye otras instalaciones.
