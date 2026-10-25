# Fase 13 — Delimitación verificable de la superficie USB

**Objeto:** comprobar qué se puede afirmar del despacho USB del bootloader A
build **169429** del Google Stadia, sin conectar hardware ni publicar su imagen.

## Resultado con la evidencia existente

`tools/audit_usb_surface.py` examina `evidence/bootloader-analysis.json`.
La selección publicada tiene **28 regiones**, **2.340 bytes de instrucciones**
de los **131.072 bytes** del bootloader (**1,785 %**), **67** llamadas directas
(donde **41** apuntan fuera de los intervalos seleccionados) y **16** sitios de
transferencia indirecta. Estas cifras cuantifican el **límite de cobertura** de
la evidencia, no la cantidad de funciones que faltan ni la superficie USB real.

**No hay una ruta USB → escritor de memoria flash demostrada.** El camino
interno documentado en fase 12 necesita un objeto IVT concreto, argumentos
fijos de desplazamiento cero y longitud 4096 bytes. Una llamada al escritor
desde una rutina de actualización no demuestra un comando USB accesible.

## Nueva herramienta para el binario local

Si el propietario facilita su `bootloader-a.bin` de 128 KiB, el mismo programa:

1. Comprueba el SHA-256 exacto
   `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`
   **antes** de aplicar interpretaciones específicas de este build.
2. Busca **candidatos** a descriptor USB Device de 18 bytes con fabricantes
   conocidos, longitudes y campos básicos coherentes; un descriptor presente
   no equivale a una interfaz activa.
3. Busca punteros absolutos alineados a esos descriptores.
4. Inspecciona el SP/reset vector en `+0x1000` y recopila destinos
   candidatos de la tabla de vectores.
5. Hace un recorrido **heurístico y limitado** de instrucciones ARM Thumb
   desde esos destinos; identifica cargas literales que referencien posibles
   descriptores, llamadas directas y transferencias indirectas sin resolver.

**Limitaciones:** no resuelve saltos mediante tablas, alias complejos,
control dinámico de USB ni la semántica de todas las instrucciones. El
recorrido puede incluir falsos positivos y omitir funciones legítimas. No
identifica por sí solo un despachador de comandos, y no puede asegurar
accesibilidad desde dispositivos externos. El código nunca abre un USB
ni escribe flash o fusibles.

## Cómo ejecutar en Windows

Con Python 3.11+ y desde la raíz del repositorio:

```powershell
py -m pip install -r requirements.txt
py tools/audit_usb_surface.py > fase13-publico.json
py tools/audit_usb_surface.py --bootloader local/bootloader-a.bin > fase13-local.json
py -m unittest discover -s tests -v
```

**El archivo debe permanecer en `local/`**, que está ignorado por Git.
No publicar binarios extraídos, números de serie o volcados completos.
Si no se dispone de la imagen local, ejecutar solamente la primera orden
de análisis y la suite.

## Qué cuenta como progreso real

- Identificar por desensamblado el procesamiento real de solicitudes USB en
  el bootloader firmado, con direcciones, llamadas y origen de los parámetros.
- Seguir un dato controlable desde una entrada externa hasta la operación
  de almacenamiento, incluidas validaciones y autenticación.
- Determinar si la ruta de escritura es alcanzable en producción antes de
  proponer pruebas en hardware.

**No se ha demostrado salto de firmas HAB CLOSED ni ejecución de firmware propio.**
