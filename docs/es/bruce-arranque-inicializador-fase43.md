# Fase 43 — Cadena firmada de arranque e inicialización del callback secundario

**26/10/2026 · PR #45 · Investigación offline, exclusivamente sobre la imagen OEM Bruce firmada original.**

## Resultado: reconstruida la cadena estática que instala el callback predeterminado

El barrido de instrucciones Thumb iniciado en **cada posición de media palabra** encontró la llamada que el anterior desensamblado lineal había omitido. Posteriormente se identificó su registro en una tabla de funciones, el bucle original que la recorre y una llamada directa desde código temprano a dicho bucle.

### Cadena verificada por instrucciones de la imagen OEM

1. **Código temprano:** `0x6004C742: BL 0x600CDB74`, llamada directa a la rutina que recorre los inicializadores.
2. **Recorrido de tabla:** `0x600CDB74` lee los límites firmados en `0x600CDBB4` y `0x600CDBB8`, que contienen respectivamente **`0x6013D4F0`** y **`0x6013D5A4`**. Calcula `(fin-inicio)/4 = 45` entradas y ejecuta `LDR.W R3,[R6,R5,LSL#2]` en `0x600CDBA2` seguido de `BLX R3` en `0x600CDBA6`.
3. **Entrada 21 (desde cero):** la palabra de la imagen en `0xFD544` (`0x6013D544`) contiene el puntero Thumb **`0x600748ED`**. Esta entrada está incluida en la región exacta recorrida por el bucle.
4. **Función envoltorio:** `0x600748EC` carga **`R4 = 0x200064C0`** del literal original `0x60074904`, copia `R4` a `R0` y ejecuta `0x600748F2: BL 0x60073BF0`.
5. **Inicializador global:** `0x60073BF0` conserva `R0` y, mediante las instrucciones verificadas en fase 42, escribe **`0x600D4F05`** en `0x200064C0+0x3A38 = 0x20009EF8` y **cero** en `0x200064C0+0x3A3C = 0x20009EFC`.
6. **Consumo posterior:** la función firmada de clase 10 `0x600613FC` lee la primera palabra, la compara con el sentinela `0x600D4F05` y evita la llamada indirecta si conserva ese valor.

**Importante:** es una cadena estática enlazada con instrucciones y palabras originales firmadas, no una traza de ejecución del dispositivo real. La imagen analizada es un archivo de actualización, no un volcado de la flash actualmente instalada. La llegada física al código temprano, el recorrido completo sin fallos, el valor de RAM al arrancar y el uso real de la clase 10 en EP0 siguen sin medirse.

### Corrección de la fase 42

La fase 42 afirmaba que no había llamadas `BL` al inicializador `0x60073BF0` **en el barrido lineal que realizó**. No era una ausencia global: la función `0x600748F2` contiene una llamada directa. La discrepancia se debe al método anterior, que desensamblaba XIP por fragmentos con un único punto de alineación y podía desincronizarse por datos literales embebidos.

La fase 43 comprueba cada posible ubicación de media palabra con un prefiltro de opcodes Thumb de salto de 32 bits, y verifica los candidatos con Capstone. Este método también puede decodificar datos como instrucciones; por ello la llamada se valida por separado con anclas semánticas y código envolvente. La función inicializadora no tiene por qué disponer de puntero estático a su propia entrada; en este caso el puntero a su **envoltorio** sí existe en la tabla de inicialización.

### Límites y criterio siguiente

- El código de arranque firmado contiene la llamada a la rutina de tabla, y la tabla contiene el inicializador del callback. No se ha medido el recorrido real en la placa.
- El valor inicial documentado es un **sentinela que devuelve cero**. No es por sí mismo una vía de ejecutar firmware propio.
- Falta localizar **posibles escrituras posteriores** en `0x20009EF8/FC` y demostrar, en su caso, la procedencia de los valores y si una entrada externa puede controlarlos.
- Siguen sin demostrarse ejecución de código no firmado, elusión HAB CLOSED, recuperación fiable de firmware o compatibilidad Xbox/Switch 2.
- Se mantienen prohibidas las pruebas de escritura o carga en el mando físico sin una ruta recuperable previamente acreditada.

## Reproducción

```bash
python -m unittest tests.test_bruce_init_inbound_phase43 tests.test_bruce_init_table_phase43 -v
python -m tools.audit_bruce_init_inbound_phase43 local/bruce_pvt_a_prod_signed.bin --out local/phase43-inbound.json
python -m tools.audit_bruce_init_table_phase43 local/bruce_pvt_a_prod_signed.bin --out local/phase43-table.json
```

Las herramientas exigen la identidad exacta de la imagen OEM original mediante SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. La CI descarga, valida y elimina los binarios temporales, sin conectarse al mando.

**Evidencia:** [PR #45](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/45).
