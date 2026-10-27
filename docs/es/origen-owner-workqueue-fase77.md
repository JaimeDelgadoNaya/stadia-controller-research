# Fase 77 — Procedencia del objeto Work Queue dentro del owner y guardas de publicación

**27 de octubre de 2026.** Auditoría **exclusivamente offline** del Bruce OEM original firmado, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa los [productores fase 75](productores-workqueue-fase75.md) y la [procedencia fase 76](procedencia-llamadores-workqueue-fase76.md).

## Descubrimiento principal: la activación original prepara el objeto B dentro del owner

La fase 76 había encontrado la asignación firmada del callback `0x6006B291` al objeto B. La fase 77 demuestra **una llamada directa original anterior** desde la ruta de activación estudiada en fase 66 al constructor del mismo objeto:

```asm
0x600747B0 MOV   R0,R7
0x600747B2 BL    0x60060F28         ; escritor de modo previo fase 66
0x600747B6 ADD.W R0,R5,#0x39C0
0x600747BE ADD.W R5,R5,#0x3F00
0x600747C4 ADDS  R5,#4
0x600747D2 BL    0x6006B2E8        ; helper anterior: NO ejecutado en fase 77
0x600747D6 MOV   R0,R5
0x600747D8 BL    0x6006B3E8        ; constructor B, referencia directa original
```

**Relación aritmética verificable bajo las entradas virtuales heredadas de fase 66:**

| Concepto | Dirección |
|---|---|
| Base global usada en fase 66, `GLOBAL` | `0x200064C0` |
| Owner del motor USB de fase 66 | `0x2000A2A8 = GLOBAL+0x3DE8` |
| Argumento original de constructor B | `GLOBAL+0x3F04 = 0x2000A3C4` |
| Desplazamiento respecto al owner | **`+0x11C`** |

Por tanto el código firmado calcula para B una ubicación **`owner+0x11C`** en el mismo estado inicial virtual modelado en fase 66. **No hemos ejecutado ese constructor encadenado desde la activación**, ni observado esa dirección en la RAM física del mando. Esta relación identifica una estructura embebida en el owner bajo el modelo; **no demuestra que la clase 10, EP0 ni un paquete USB active el constructor**.

## Inicializador B: método firmado y dos indicadores

La función original **`0x6006B3E8`** guarda el argumento inicial como R4 y primero lee **`[R0+0x180]`**. Si ese byte ya está activado, toma un retorno temprano. En el camino de inicialización aparecen estos anclajes de código original:

```asm
0x6006B416 LDR   R3,[PC,#0x9C]        ; literal original 0x6006B291
0x6006B41C STR.W R4,[R4,#0x120]       ; contexto original
0x6006B420 STR.W R3,[R4,#0x11C]       ; callback OEM
0x6006B43E MOVS  R3,#1
0x6006B442 STRB.W R3,[R4,#0x180]      ; indicador local
```

El callback original `0x6006B290`, estudiado en fase 76, consulta otro byte **`[R4+0x182]`** en `0x6006B29C` y lo pone a cero en `0x6006B2C2` tras sus bifurcaciones. Un barrido Thumb acotado a `0x6006A000..0x6006D000` encuentra esas dos instrucciones con forma de acceso literal a `+0x182`. **No excluye otros escritores fuera de ese rango o con alias calculados**. Los bytes `+0x180` y `+0x182` son indicadores **distintos**.

El censo XIP muestra un **BL directo** a B desde `0x600747D8`; no muestra otro `BL` directo a la entrada exacta `0x6006B3E8` dentro de la región escaneada. Este resultado no cubre funciones indirectas, alias o caminos no ejecutados.

## Productor A: entrada y condición adicional

La ventana de código firmada de A, cuya entrada candidata está en **`0x60062126`**, conserva:

- `0x60062128 MOV R5,R0`: el puntero del byte atómico proviene del argumento entrante R0.
- `0x6006212C MOV R4,R2`: el argumento de trabajo que finalmente se pasa como `R4+0x10` deriva del argumento R2.
- `0x60062264 UXTB R0,R0; 0x60062266 CMP R0,#0x0E; 0x60062268 BNE`: el flujo requiere también el resultado **`0x0E`** para continuar.
- `0x60062272 LDREXB` y `0x60062276 STREXB`: después se exige que el byte anterior sea cero para publicar el trabajo `0x6006228C BL 0x600926A0`.

Estos hechos justifican **procedencia local de registros**, no el origen anterior de los argumentos. El barrido de `BL` directo hacia la entrada candidata de A no recuperó llamadores, por lo que **aún no sabemos de qué periférico o flujo llega R0/R2**, ni se ha observado la ejecución física del bloque.

## GO / NO-GO y siguiente fase

**Resultado de fase 77:** el segundo objeto de trabajo tiene una **localización relativa al owner USB modelado** y un constructor de callback **original firmado**, con ruta directa desde la activación. Es un progreso significativo en la reconstrucción de estructuras. **No hay puente acreditado paquete USB físico → mensaje en la cola → callback** ni control del puntero de función desde el host.

**Criterio de parada de esta línea como ejecución propia:** seguir reconociendo funciones internas no basta. Si una investigación acotada del productor A y de las entradas del constructor B no encuentra un origen USB real, priorizar evidencia pasiva de tráfico/estado USB y un puente externo en lugar de presentar la Work Queue como vulnerabilidad.

Quedan sin demostrar firmware no firmado ejecutable, bypass HAB CLOSED, recuperación de instalación y compatibilidad nativa Xbox/Switch 2.

## Reproducción y evidencia

```bash
python -m pip install -r requirements-emulation.txt
python -m tools.audit_workqueue_owners_phase77 local/bruce.bin --out local/phase77-owner.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_workqueue_owners_phase77 -v
```

[Evidencia estructurada](../../evidence/usb-workqueue-owner-origin-phase77.json) · [PR #79](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/79) · [Auditoría original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40478927390).

**Sin operaciones USB sobre el mando, RAM física, flasheo ni eFuses.**
