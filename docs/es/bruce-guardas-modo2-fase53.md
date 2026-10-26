# Fase 53 — Guardas necesarias de entrada al modo USB 2 (Bruce OEM)

**26 de octubre de 2026.** Auditoría solo de lectura de la actualización OEM original Bruce, **SHA-256** `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No se han enviado solicitudes USB ni escrito en el hardware.

## Hallazgo: un modo solicitado no implica entrada al constructor

La fase 52 acreditó una ruta **condicional** que escribe `[0x20004084] = 0x2000A2AC` durante el registro de configuración USB. La fase 53 explicita las **condiciones necesarias anteriores**, que en la fase 52 quedaban abiertas como ramas con RAM desconocida.

En el firmware original:

```asm
0x60060FEC  LDR.W R3,[R0,#0x90]  ; modo anterior en owner+0x90
0x60060FF0  MOV R4,R0             ; owner
0x60060FF2  MOV R5,R1             ; modo solicitado
0x60060FF4  CMP R3,R1
0x60060FF6  BEQ 0x6006107C      ; si ya es el mismo, salir
0x60060FF8  CMP R3,#0
0x60060FFA  BEQ 0x6006107C      ; si el anterior es 0, salir
...
0x60061020  CMP R5,#2
0x6006102A  BNE 0x60061080
0x6006102E  BL 0x60060F84       ; constructor, únicamente en la rama modo 2
```

De estas comparaciones se obtiene la condición necesaria (no suficiente):

```text
modo_solicitado == 2
Y modo_anterior != 0
Y modo_anterior != modo_solicitado
```

La lectura previa está en **`owner+0x90 = 0x2000A338`**. La imagen de actualización no contiene su valor en el mando físico.

| Modo anterior hipotético | Solicitar modo 2 | ¿Supera estas guardas iniciales? |
|---|---|---|
| 0 | 2 | No |
| 1 | 2 | Sí, únicamente las guardas iniciales |
| 2 | 2 | No |
| 3 | 2 | Sí, únicamente las guardas iniciales |

**Un «sí» no significa que el constructor se haya ejecutado:** quedan por delante llamadas OEM, estado de hardware, comprobaciones y resultados dinámicos que no se conocen.

## Dos escrituras distintas al campo de modo

- `0x6006101C: MOVS R7,#1`, seguida de `0x60061022: STR.W R7,[R4,#0x90]`: el código firmado tiene una **escritura transitoria condicional de valor 1** al mismo campo antes de entrar al constructor.
- `0x60061070: STR.W R5,[R4,#0x90]`: otra ruta escribe el **modo solicitado** posteriormente, tras controles de retorno e inicialización. Con solicitud 2, su valor sería 2 **si se toma esa ruta**.

Esto evita interpretar una escritura a modo 1 como demostración de modo 1 final o confundir la petición de modo 2 con su configuración efectiva.

## Guarda independiente en la configuración compartida

El constructor `0x600550E4` lee **`[owner+8] = [0x2000A2B0]`** y, en `0x600550FA`, toma la salida si es cero. La función `method_guard()` documenta esa condición necesaria: **no nulo no quiere decir puntero ejecutable válido** ni demuestra quién lo inicializó.

La comparación de modos y la lectura del método son condiciones **necesarias, no una demostración del camino completo**. Las funciones auxiliares del modo 2 y sus retornos siguen sin modelarse plenamente.

## Qué se ha ganado y qué falta

Ahora sabemos **por qué una llamada solicitando modo 2 puede no registrar la configuración USB**, incluso cuando existe el constructor firmado. Una observación física del modo actual deberá distinguir el estado anterior, las escrituras transitorias y la configuración final.

Continúa sin acreditarse quién escribe los valores de `owner+4/+8/+12`, qué contiene la lista activa, si clase 10 es seleccionada por EP0 en hardware, ni ninguna ejecución no firmada o bypass de **HAB CLOSED**.

**Siguiente objetivo:** revisar inicializadores efectivos del método `owner+8` y de la lista de clases. Si el análisis estático no basta, recopilar **solo enumeración y descriptores USB mediante un lector pasivo**, sabiendo que esos descriptores no equivalen a un volcado de RAM.

## Reproducir

```bash
python -m unittest tests.test_bruce_mode2_preconditions_phase53 -v
python -m tools.audit_bruce_mode2_preconditions_phase53 local/bruce_pvt_a_prod_signed.bin --out local/phase53-guards.json
```

La auditoría rechaza una imagen cuya longitud o hash no coincida. Los 27 anclajes son instrucciones firmadas originales y se comprueban contra el archivo OEM exacto; los casos de prueba son escenarios hipotéticos, **no mediciones del mando**.

[Evidencia estructurada](../../evidence/bruce-mode2-preconditions-phase53.json).
