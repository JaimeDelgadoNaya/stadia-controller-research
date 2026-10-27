# Fase 78 — Inicializador compartido de Work Queue: explicación del enlace con USB

**27 de octubre de 2026.** Auditoría exclusivamente offline del **Bruce OEM firmado original**, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 77](origen-owner-workqueue-fase77.md).

## Hallazgo principal

El auxiliar compartido **`0x6009267C`** es una rutina que examina el *handle* global de la **Work Queue** y, si este está vacío, entra en su vía de creación. El mismo auxiliar aparece en la inicialización de modo USB y del objeto B porque ambos solicitan el servicio global, **sin que ello acredite un evento USB recibido ni una relación de causa-efecto entre las rutas**.

Los dos argumentos de entrada se preparan mediante **código firmado**:

| Llamador | Procedencia del argumento |
|---|---|
| `0x60060F34`, escritor de modo estudiado en fase 66 | `0x60060F28 MOVS R3,#1` y `0x60060F32 MOV R0,R3`: pasa **R0=1** |
| `0x6006B400`, inicializador B de fases 76–77 | `0x6006B3FE MOVS R0,#1`: pasa **R0=1** |

La firma del auxiliar queda anclada a **16 instrucciones originales**. En particular:

```asm
0x6009267C  MOV  R2,R0                ; conserva el 1 del llamador
0x6009267E  LDR  R0,[PC,#0x18]      ; literal 0x60092698 = 0x2002014C
0x60092682  LDR  R1,[R0,#0x58]      ; lee el handle
0x60092684  CBNZ R1,#0x60092692    ; si ya existe, omite crear
0x60092686  LDR  R1,[PC,#0x14]      ; literal 0x6009269C = 0x6012F592
0x60092688  BL   0x6010177A       ; camino de creación: NO ejecutado aquí
0x60092692  MOV.W R0,#0            ; retorno del camino con handle
0x60092696  POP  {R3,PC}
```

La cadena original situada en `0x6012F592` es **«Work Queue Task»**. Estos literales estaban previamente documentados en fase 67; esta fase confirma mediante ejecución acotada la guarda de inicialización y la **igualdad de los parámetros de ambos llamadores**.

## Experimento: dos ramas originales en emulación

Se ejecutó `0x6009267C` en Unicorn con XIP original y RAM **virtual**. El estado de entrada `R0=1` proviene de ambos llamadores originales, pero el valor del handle se estableció expresamente como **vector de prueba**, sin pretender representar la RAM real.

| Caso | Handle virtual `[0x2002014C+0x58]` | Instrucciones originales ejecutadas | Resultado |
|---|---|---|---|
| Sin tarea creada | `0` | Desde `0x6009267C` hasta `0x60092688` | **Parada en `0x6010177A`**, antes de ejecutar su primera instrucción |
| Tarea ya creada | `0x20025000` (*fixture*) | Desde `0x6009267C` hasta `0x60092696` | Retorno normal con `R0=0` |

Con handle cero y parada en creación, los argumentos son **`R0=0x2002014C`, `R1=0x6012F592` y `R2=1`**. En ambos casos el handle virtual queda inalterado. El camino con handle no nulo ni siquiera entra en la creación.

El experimento **no ejecuta** `0x6010177A`, la creación de tareas, el planificador, las recepciones de cola, callbacks ni llamadas USB. No se han introducido mensajes ficticios.

## Decisión técnica: explicación del helper compartido

El hallazgo nuevo acota el «puente» sugerido por las fases 66–77: **la existencia de un servicio global de inicialización basta para explicar la llamada común**. Los llamadores pueden usar el mismo objeto Work Queue sin que ninguno tenga que recibir o publicar un paquete USB. El código original aún admite otras rutas no inspeccionadas, por lo que **no se demuestra imposibilidad de un vínculo USB**.

Para plantear ejecución propia faltan pruebas independientes: **un paquete USB real**, un productor que publique el elemento correspondiente, una recepción, un callback efectivamente llamado, control del destino por el host y una vía compatible con **HAB CLOSED**.

**Criterio de corte:** despriorizar como hipótesis de ejecución controlada la simple coincidencia del helper. El siguiente esfuerzo útil es identificar entradas y emisores USB reales mediante captura **pasiva**, comparar las trazas con clases/endpoints conocidos y evaluar el puente Stadia→Xbox por separado. Si no hay evidencia de origen USB, no consumir más fases en «proximidades» de código sin relación causal.

## Artefactos y verificación

- `tools/audit_workqueue_shared_init_phase78.py`: SHA fail-closed; 16 anclas, dos literales originales, conexiones firmadas 66/77 y dos emulaciones de guardas con puntos de parada.
- `tests/test_workqueue_shared_init_phase78.py`: pruebas de anclas, hash, ramas y evidencia reproducible.
- [Evidencia de ambas ramas](../../evidence/usb-workqueue-shared-init-phase78.json) obtenida en [GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40486798083).
- [PR #80](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/80).

**Sin peticiones físicas al mando, lecturas de RAM instalada, escrituras flash/eFuse, ejecución personalizada ni bypass HAB CLOSED.**
