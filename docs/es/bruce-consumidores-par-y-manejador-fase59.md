# Fase 59 — ¿Quién usa el par función/contexto? Resolución del manejador real

**26/10/2026.** Auditoría **sin hardware**, contra la actualización OEM Bruce firmada original y fijada por SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Resumen de resultados

La fase 58 demostró una ruta de **escritura condicionada** del par global de dos palabras:

- `0x2000FBF4`: puntero con formato Thumb, `0x600CE233` o `0x0000A9C5`.
- `0x2000FBF8`: contexto `0` o dirección de un objeto dinámico.

La fase 59 buscó una ruta para leer/invocar esos valores. **No se ha demostrado una lectura de este par ni una invocación indirecta desde él.** Esta es una conclusión **limitada al barrido documentado**, no una afirmación de ausencia en todo el firmware. La investigación original confirma por separado a dónde lleva el puntero ITCM.

## 1. Barrido de literales directos del par

La actualización OEM original contiene **8 palabras alineadas** cuyo valor es exactamente la base de la estructura `0x2000F878`. De ellas, **10 instrucciones con la forma `LDR Rn,[PC,#desplazamiento]`** pueden cargar la base. La lista incluye el escritor original `0x60063874` y varios usos de otros campos de esa estructura.

**No se ha encontrado** un literal alineado cuyo valor absoluto sea `0x2000FBF4` o `0x2000FBF8`. Esto **no descarta** direcciones calculadas a partir de la base, alias indirectos, acceso por índices o código en otras regiones.

## 2. Control de calidad: scan Thumb en cada posición de media palabra

El desensamblado lineal inicial omitió **ambas escrituras conocidas** del backend `0x6006386C`; por eso se descartó como prueba de ausencia. Un segundo auditor reinicia el decodificador en **cada posición alineada a 2 bytes** en XIP y en el bloque relocalizado a ITCM. Exige recuperar, bajo pena de error:

```asm
0x60063878 STR.W R2,[R3,#0x37C] ; 0x2000FBF4, si R3=0x2000F878
0x6006387E STR.W R2,[R3,#0x380] ; 0x2000FBF8
```

Resultado: **11 coincidencias de instrucciones con la forma de acceso a `+0x37C` o `+0x380`**, incluidas esas escrituras. No todas representan código alcanzable; algunas pueden ser bytes de datos desensamblados.

De las 11, solo **una** tiene forma de lectura directa: `0x600BD138 LDRB.W R3,[R3,#0x380]`.

## 3. El único lector directo identificado usa otra base

La auditoría fija cuatro instrucciones originales del entorno `0x600BD128–0x600BD138`. El lector carga su base mediante `0x600BD136 LDR R3,[PC,#0x10]`; la palabra literal original se encuentra en **`0x600BD148`** y vale:

```text
Base real utilizada por ese lector: 0x20025CE0
Base del par investigado:          0x2000F878
¿Son iguales?                      NO
```

También hay una escritura de byte `0x600BD12C STRB.W R3,[R2,#0x380]` con ese mismo literal de base. Por tanto **este acceso directo no puede atribuirse a nuestro par usando su procedencia literal**. No descartamos alias o cambios dinámicos no modelados.

No se ha verificado ningún `LDR` directo de `[0x2000F878+0x37C]` ni un `BLX` cuya fuente esté probadamente vinculada a esa pareja. **No significa que no existan accesos mediante otros cálculos.**

## 4. El puntero ITCM es un veneer, y hemos resuelto su destino real

La fase 58 había encontrado que la opción activa de la pareja puede escribir `0x0000A9C5`. Se fijó su entrada `0xA9C4 B.W 0xB980`.

En **`0xB980`** no hay una función de trabajo convencional, sino un **veneer**:

```text
0x0000A9C4: B.W 0xB980
0x0000B980: LDR.W PC,[PC,#-0x0]
0x0000B984: literal original 0x6007E6A1  (DATOS)
                          ↓
0x6007E6A0: rutina XIP firmada real
```

El literal se obtiene de los bytes de origen ITCM copiados por el arranque: desplazamiento **`0xC1A0`** del archivo firmado. Se evita tratar las palabras de la tabla de saltos como instrucciones ordinarias, un error que distorsionaba la primera vista lineal.

Se han añadido **13 anclas originales** a la rutina XIP `0x6007E6A0`. Esta:

- Examina un indicador del objeto en `+0x6C`.
- Comprueba bits de un campo de estado en `+0x70`.
- Utiliza operaciones atómicas `LDREX/STREX` sobre una palabra en `+0x74`.
- En ciertas rutas llama a funciones firmadas como `0x60101B76` y `0x6013D138`.

Esto es **compatible con lógica de estado/ejecución diferida de un objeto**, pero **no acredita** que se lance mediante un paquete USB, que lea el par global, que acepte punteros del host o que ejecute firmware no firmado.

## Decisión de investigación

**La hipótesis de un callback directamente controlable desde USB mediante este par NO se sostiene todavía con evidencia suficiente.** Hemos confirmado quién **puede escribir** el par y cómo es el manejador firmando de la opción ITCM. Falta probar un **consumidor del par** y, después, un **origen USB concreto** de esa invocación.

Para la **fase 60**, limitaría la investigación a una vía concreta: analizar lectores por **alias calculados** de `0x2000F878` y una ruta de evento hacia `0x6007E6A0`. Si no aparece vínculo, cerraría esta rama como candidato a ejecución por USB y priorizaría evidencia física **pasiva y reversible** (enumeración USB sin escrituras).

La clase 10 activa, `owner+4/+8/+12`, cualquier ruta para ejecutar código propio, la compatibilidad nativa Xbox/Switch 2 y bypass HAB CLOSED **siguen sin demostrarse**.

## Reproducción

```bash
python -m unittest tests.test_bruce_pair_consumers_phase59 -v
python -m tools.audit_bruce_pair_consumers_phase59 local/bruce_pvt_a_prod_signed.bin --out local/phase59-consumers.json
```

[PR de fase 59](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/61) · [Auditoría sobre Bruce OEM original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40368779599) · [Evidencia estructurada](../../evidence/bruce-pair-consumers-phase59.json).

**Seguridad:** no se han enviado comandos USB, ni realizado volcados de RAM física o escrituras de flash/eFuses.
