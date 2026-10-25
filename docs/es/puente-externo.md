# Fase 32 — Continuación reversible y compatibilidad con consolas

Fecha: 2026-10-25. La prioridad del propietario es utilizar el mando en las
consolas compatibles. La fase 31 sigue cerrada: no hay firmware propio ejecutable
demostrado en el mando. Esta fase prepara herramientas y alternativas externas.

## Resultado reproducible

Se ha inspeccionado y preparado una copia independiente de
[stadia-dongle-esp](https://github.com/danzig666/stadia-dongle-esp/tree/d8392de8f838e12cf16c985b9beb8080c7acd970),
fijada al commit `d8392de8f838e12cf16c985b9beb8080c7acd970`.
Su código contiene un receptor BLE NimBLE, traducción de entradas Stadia y una
interfaz USB Xbox 360 mediante TinyUSB. También implementa rutas de vibración,
teclado y ratón. Su funcionamiento físico con nuestro mando sigue sin probarse.

Desde la raíz del repositorio, con Python 3.10+ y Git:

```sh
python tools/prepare_external_bridge.py local/stadia-dongle-esp
python tools/prepare_external_bridge.py local/stadia-dongle-esp --verify-only
python -m unittest discover -s tests -v
```

La herramienta comprueba el commit y nueve hashes SHA-256 registrados en
[el manifiesto](../../evidence/external-bridge-source.json), y rechaza destinos
no vacíos. Descarga código; no compila, no instala drivers ni programa dispositivos.
Conserva el proyecto GPL-3.0 separado del repositorio de investigación MIT.
La comprobación cubre identidad de fuentes seleccionadas, no una auditoría
completa ni reproducibilidad de un binario.

## Qué falta para el prototipo

El upstream requiere ESP32-S3 con USB nativo, al menos 4 MB de flash y ESP-IDF
6.x. No se ha confirmado que el propietario disponga de esa placa; tampoco se
ha compilado ni programado. El mando debe tener modo Bluetooth disponible:
ver la versión por USB no demuestra que se pueda emparejar por BLE.

En una terminal ESP-IDF, dentro de la copia preparada, los comandos upstream
para construir son `idf.py set-target esp32s3` e `idf.py build`. Se deben registrar
la versión exacta del SDK, el resultado y los hashes del binario antes de una
prueba física. El instalador web sigue el upstream actual y no sustituye este pin.

La salida Xbox 360 del prototipo está dirigida a PC. Para elegir una consola,
usar la [matriz de compatibilidad](compatibilidad-consolas.md), que distingue
las declaraciones de fabricantes de las pruebas locales.

## Prueba física pendiente

1. Registrar placa, SDK, commit y binario construido.
2. Verificar enumeración USB y emparejamiento BLE con el mando.
3. Comprobar cada botón, cruceta, centro y extremos de sticks y gatillos.
4. Comprobar vibración y neutralización al desconectar; repetir reconexiones.
5. Probar la combinación exacta de consola, adaptador y firmware seleccionada.

Las frecuencias BLE anunciadas por upstream no son una medición de latencia
extremo a extremo. Audio, micrófono y compatibilidad de consola no se deducen
de que se traduzcan botones.

Para comprobar entradas USB actuales en Windows sin placa adicional, usar
[el diagnóstico de entrada](diagnostico-entrada.md).
