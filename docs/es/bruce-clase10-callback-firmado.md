# Fase #40 — origen firmado del callback de clase 10 en el mando Stadia

**26 de octubre de 2026.** Análisis exclusivamente offline de la imagen de **actualización** OEM Bruce firmada original, 1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. **No es una lectura de la flash real del mando**, ni se ha enviado ningún comando USB.

## Hallazgo principal: primera palabra de la entrada de 12 bytes localizada

La [fase #39](bruce-clase10-origen-r1.md) demostró estáticamente que `0x60055320`, el inicializador de clase 10, recibe la dirección de un registro interno `R1`, de 12 bytes, y almacena ese puntero en el objeto de clase. La fase anterior no había identificado el **escritor de `registro+0`**.

Ahora se ha encontrado una entrada candidata **completamente inicializada en el archivo firmado, no escrita por USB**:

| Campo | Desplazamiento origen | Dirección esperada en RAM tras la copia de inicio | Contenido firmado |
|---|---|---|---|
| Registro clase 2, función `+0` | `0xFDF50` | `0x200030E8` | `0x60061249` |
| Registro clase 2, objeto `+4` | `0xFDF54` | `0x200030EC` | `0` |
| Registro clase 2, descriptor `+8` | `0xFDF58` | `0x200030F0` | `0x200030A0` |
| **Registro clase 10, función `+0`** | **`0xFDF5C`** | **`0x200030F4`** | **`0x600613FD`** |
| Registro clase 10, objeto `+4` | `0xFDF60` | `0x200030F8` | `0` |
| Registro clase 10, descriptor `+8` | `0xFDF64` | `0x200030FC` | `0x20003100` |

Los descriptores aludidos están también en la copia de datos inicializados: byte `[0x200030A0+4]=2` y byte `[0x20003100+4]=10`. Son exactamente los selectores 2 y 10 comprobados en el registro de clases firmado de las fases #37–#38.

**Resultado:** hemos resuelto para esta **entrada original de clase 10** la primera palabra que antes faltaba: el puntero Thumb `0x600613FD` a la función del firmware firmado **`0x600613FC`**. Es una dirección fija en la imagen OEM, no un puntero elegido directamente por el valor `bRequest`.

### Evidencia adicional de la selección de esta tabla

El mismo original contiene dos palabras literales con `0x200030E8`, en offsets `0x21100` y `0x21108`. Aparecen justo después de rutinas Thumb `LDR R0,[PC,#0]; BX LR`, compatibles con funciones que devuelven la dirección inicial de los registros contiguos. En el offset `0x213F8` existe asimismo una palabra `0x200030F4`, la dirección de la entrada de clase 10. **Son referencias estáticas**, no prueba de que se llame realmente a esas rutinas durante el arranque.

## Se inspeccionó la función original `0x600613FC`

La desensambladura de la imagen original muestra las instrucciones siguientes, sin necesidad de interpretar como código las palabras literales contiguas:

```asm
0x600613FC  CMP    R1,#0x7F
0x600613FE  PUSH   {R4,LR}
0x60061400  BLS    0x60061422       ; peticiones <= 0x7F: retorno 0
0x60061402  LDR    R0,[PC,#0x24]  ; base global RAM
0x60061404  MOVW   R3,#0x3A38
0x60061408  LDR    R4,[PC,#0x20]  ; valor de referencia/sentinela
0x6006140A  LDR    R3,[R0,R3]     ; callback registrado en RAM
0x6006140C  CMP    R3,R4
0x6006140E  BEQ    0x60061422
0x60061410  MOVW   R4,#0x3A3C
0x60061414  LDR    R0,[R0,R4]     ; contexto registrado
0x60061416  BLX    R3             ; llamada indirecta, si pasa guardas
0x60061422  MOVS   R0,#0
```

Por tanto los códigos de solicitud sintéticos **`0x81,0x83,0x84` superan el filtro inicial** porque son mayores que `0x7F`. La función **no ofrece por sí misma un intérprete arbitrario de esos códigos**. Consulta una **segunda función registrada en RAM**, comprueba su valor frente a una referencia y solo entonces puede delegar el trabajo.

Las palabras literales del firmware en `0x60061428` y `0x6006142C` valen **`0x200064C0`** y **`0x600D4F05`**, respectivamente. Así, la lectura del segundo callback se realiza en **`0x20009EF8`** (`0x200064C0 + 0x3A38`) y la de su contexto en **`0x20009EFC`** (`+0x3A3C`). La comparación comprueba el puntero contra **`0x600D4F05`**, una palabra de control firmada. Estas direcciones son estáticas; sus contenidos efectivos en RAM siguen sin conocerse. Una emulación acotada del código OEM comprueba las guardas con registros sintéticos y se detiene siempre antes del salto `BLX R3`.

Esta **segunda dirección y su contexto durante la ejecución física** siguen sin medirse. No está demostrado que el host pueda sobrescribirla, que el manejador esté activo en EP0 o que ese salto permita ejecutar instrucciones no firmadas.

## Alcance y calidad de las pruebas

`tools/audit_bruce_class10_record_producer.py`:
- exige el tamaño y SHA-256 exactos del Bruce firmado;
- examina registros triples candidatos en la región de tablas XIP y en los datos que el arranque copia a RAM;
- valida explícitamente las dos entradas **contiguas**, el tamaño de 12 bytes, los descriptores y selectores 2/10;
- reconstruye las referencias literales `0x200030E8` y `0x200030F4`;
- valida las instrucciones de filtro e indirección de `0x600613FC` y obtiene los valores de sus literales;
- separa los resultados confirmados de las coincidencias estructurales y del estado físico todavía desconocido.

En los datos de arranque se detectaron **73 coincidencias de forma**, pero **solo una coincidencia** con la restricción adicional de byte `+4 =10`, precisamente la de `0x200030F4`. En la zona estática XIP inspeccionada, 522 coincidencias de forma y ninguna que satisficiera esa misma condición. **Estas cifras dependen de los límites de búsqueda y del modelo elegido; no demuestran unicidad absoluta en todo el firmware.**

## Decisión y siguiente comprobación

Este hallazgo reduce significativamente la incertidumbre anterior: **el callback inicial de la entrada de clase 10 sí está fijado en el firmware firmado original**. No necesitamos seguir buscando otro escritor para esa entrada de inicialización concreta.

El siguiente objetivo es resolver la **segunda dirección de callback en RAM**, cargada en `0x6006140A`, identificar la rutina que la registra y comprobar si su contenido depende de parámetros del host o de código OEM firmado. Solo entonces se podrá valorar una vía de ejecución propia.

**Sin demostrar:** arranque de firmware sin firma en HAB CLOSED, ejecución personalizada, instalación segura, recuperación tras fallos, alcance USB físico de `0x81/0x83/0x84` o compatibilidad directa Xbox/Switch 2. Nunca se ha escrito en el mando durante esta fase.

## Reproducción

```sh
python -m unittest tests.test_bruce_class10_record_producer -v
python -m tools.audit_bruce_class10_record_producer local/bruce_pvt_a_prod_signed.bin --out local/class10-record-builder.json
```

[PR #40](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/40). El workflow utiliza copias temporales firmadas verificadas por SHA-256 que se eliminan al terminar.
