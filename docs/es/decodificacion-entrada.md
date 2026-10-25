# Decodificación offline de entrada Stadia

[English](../en/input-decoding.md)

El descriptor medido permite interpretar los 11 bytes del informe USB ID 3.
La herramienta propia `tools/decode_stadia_input.py` funciona sin abrir el mando.
Prepara la entrada para una implementación posterior; no es firmware instalable.

| Bytes incluyendo ID | Contenido |
|---|---|
| 0 | ID 3 |
| 1, nibble bajo | Hat 0–7; fuera de rango significa estado nulo |
| 2–3, bits 0–14 | Usos de botones 18,17,20,19,13,12,11,15,14,8,7,5,4,2,1 |
| 4–7 | X,Y,Z,Rz, rango declarado 1–255 |
| 8–9 | Controles de simulación HID C5,C4, rango 0–255 |
| 10, bits 0–2 | Usos Consumer E9,EA,CD |

Se ignora el relleno. Los ejes cero se conservan y se señalan fuera de rango.
No se deducen etiquetas físicas A/B/X/Y, lados de gatillos, inversión de ejes,
centro real ni zona muerta. El centro 128 de los ejemplos es sintético.

```sh
python tools/decode_stadia_input.py "03 08 00 00 80 80 80 80 00 00 00"
python -m unittest discover -s tests -q
```

Seis pruebas nuevas contrastan el layout con la evidencia del descriptor,
activan cada botón por separado, cubren estados nulos/relleno, distinguen
ejes/controles y rechazan tamaños o IDs incorrectos. Total: 354 pruebas.
No se han capturado pulsaciones físicas durante esta continuación.

## Diferencia con Nintendo

El Pro original usa informes 21/30, ejes empaquetados de 12 bits y ZL/ZR
digitales. El formato Stadia necesita traducción, calibración y una máquina de
protocolo; cambiar identificadores USB no realiza esas tareas.
[Notas primarias fijadas](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_notes.md).

El controlador Linux inicializa con 80/02, 80/03, 80/02 y 80/04.
El último comando no devuelve respuesta y el driver ignora su timeout.
Es una observación con host Linux, no una captura ni aceptación en Switch 2.
[Driver primario fijado](https://github.com/torvalds/linux/blob/21a7f44fd0765fcc5194130b28767786eba1d1e7/drivers/hid/hid-nintendo.c).

Siguiente evidencia necesaria: muestras etiquetadas de reposo, una pulsación
por botón, extremos de sticks y gatillos individuales. Permitirán verificar
remapeo y umbrales ZL/ZR. La ejecución propia y la recuperación siguen pendientes.
