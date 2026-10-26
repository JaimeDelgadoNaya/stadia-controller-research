# Fase 56 — Origen de R0, envoltorio de ITCM y lectores del campo +0x80

**26 de octubre de 2026.** Auditoría sin hardware de la actualización OEM Bruce firmada, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. **No equivale a leer la RAM ni la flash instaladas.**

## Hallazgo 1: la base de objeto pasada a `0x6007EB8C` procede de una función concreta

Las **8 instrucciones originales verificadas** de `0x60079D74` a `0x60079D84` permiten seguir el valor de R0:

```asm
0x60079D74 MOVS R0,#0xA4       ; 164 decimal
0x60079D76 BL 0x6013D378     ; función productora de R0
0x60079D7A MOV R3,R5          ; no modifica R0
0x60079D7C LDR R2,[PC,#0x54]  ; literal: owner = 0x2000A2A8
0x60079D7E MOV R4,R0          ; conserva retorno de la función
0x60079D80 LDR R1,[PC,#0x54]
0x60079D82 STR R6,[SP]
0x60079D84 BL 0x6007EB8C     ; recibe R0, R2, etc.
```

**Nuevo resultado verificable:** el argumento R0 de este constructor proviene directamente del **retorno de `0x6013D378`**, llamada con el parámetro **164**. No tenemos su valor numérico en un mando físico.

La fase 55 verificó que `0x6007EB8C` conserva el R0 de entrada en R4 y transfiere owner desde R2 a R8, antes de una escritura `STR.W R8,[R4,#0x80]` en `0x6007EBB4`.

## Hallazgo 2: función productora mediante un salto a código ITCM

En `0x6013D378` el código OEM contiene `LDR.W PC,[PC,#-0x0]`. El literal siguiente **no es código que debamos desensamblar**, sino el puntero **`0x0000B533`**. Quitando el bit Thumb queda la dirección de ejecución **`0x0000B532`**.

El arranque copia el bloque OEM firmado que empieza en el desplazamiento de archivo `0x81C` a ITCM en dirección cero. Por ello los bytes que corresponden a **`0x0000B532`** están en el archivo en **`0xBD4E`**; se desensamblan con el **PC de ejecución ITCM**, no con el PC XIP del archivo.

Ruta estática confirmada de llamadas y saltos:

```text
BL 0x6013D378    (R0 = 0xA4)
          │
          ▼
LDR PC → literal 0x0000B533
          │
          ▼
ITCM 0xB532      (envoltorio)
          │
          ▼
BL 0x8832
          │
          ▼
B.W 0x7F58       (rutina interna de gestión de memoria)
          │
          ▼
Retorno dinámico R0 (valor físico desconocido)
          │
          ▼
Constructor 0x6007EB8C
          │
          ▼
[R4 + 0x80] = owner  (ruta de código firmada)
```

La auditoría verifica **15 instrucciones firmadas** del envoltorio y el salto de `0x8832`. El envoltorio convierte tamaños cero en 1, llama a `0x8832`, retorna si R0 no es cero y ejecuta rutas de tratamiento/reintento si el resultado es cero. La función interna `0x7F58` conserva el tamaño, ajusta alineación a múltiplos y consulta estructuras de memoria: **evidencia compatible con una implementación de asignación dinámica**.

No hemos emulado toda la función ni demostrado que una asignación haya tenido éxito en hardware. Por eso hablamos de **objeto aparentemente asignado dinámicamente**, no de una dirección RAM efectiva recuperada.

## Hallazgo 3: censo de consumidores de `+0x80` (sin atribuirlos al objeto)

En una pasada de desensamblado lineal por XIP se han observado **32 instrucciones candidatas** que leen `[registro,#0x80]`, de las cuales **29 son `LDR` y 3 `LDRB`**.

Ejemplos cercanos a código de la misma región:

| Dirección PC | Instrucción | Nivel de evidencia |
|---|---|---|
| `0x6007E9A4` | `LDR.W R0,[R4,#0x80]` | Candidato próximo al constructor |
| `0x6007E810` | `LDR.W R0,[R4,#0x80]` | Candidato en región cercana |
| `0x6007E7EA` | `LDR.W R0,[R0,#0x80]` | Candidato en región cercana |
| `0x6005B99C` | `LDR.W R0,[R4,#0x80]` | Candidato en otra región |

**El desplazamiento `+0x80` no identifica por sí solo un objeto.** Esas instrucciones podrían pertenecer a estructuras diferentes, y el desensamblado lineal puede interpretar bytes que no son instrucciones ejecutadas. Ninguna de las 32 lecturas está todavía vinculada por procedencia de punteros al R0 concreto de `0x60079D84`. El enlace **constructor → consumidor real → configuración USB activa** sigue **sin demostrar**.

## Balance y siguiente fase

**Ganancia:** conocemos el productor firmado de R0 y cómo llega a una rutina ITCM de asignación, que antes era una incógnita. Esto favorece la hipótesis de que el objeto contenedor es dinámico.

**Pendiente:** demostrar la identidad de las bases en `0x6007E9A4`, `0x6007E810` y `0x6007E7EA` y si las rutinas lectoras reciben el mismo objeto construido. Sigue sin identificarse quién escribe `owner+4/+8/+12`, el estado activo de clase 10, una escritura de callback controlable por ordenador, ejecución no firmada o bypass de HAB CLOSED.

**Fase 57 recomendada:** rastrear la procedencia del registro base de los lectores de la familia `0x6007E7xx–0x6007E9xx`, priorizando `0x6007E9A4`. Si el vínculo estático no puede probarse, medir descriptores USB mediante un procedimiento pasivo y reversible, sin confundir esa enumeración con una captura de RAM.

## Verificación

```bash
python -m unittest tests.test_bruce_parent_r0_phase56 -v
python -m tools.audit_bruce_parent_r0_phase56 local/bruce_pvt_a_prod_signed.bin --out local/phase56-r0.json
```

El auditor rechaza una imagen de distinta longitud/hash y verifica las anclas de la fase 55. **673 pruebas** en las dos versiones Python 3.11 y 3.12: correctas. [Auditoría original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40351166570) · [Evidencia estructurada](../../evidence/bruce-parent-r0-phase56.json).

**Sin solicitudes USB, captura de RAM, modificación de flash ni eFuses.**
