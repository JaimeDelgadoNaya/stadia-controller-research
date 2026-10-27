# Investigación paralela — mando Stadia

**Estado: organización en cinco líneas de trabajo independientes, no cinco agentes autónomos en ejecución.** Cada línea dispone de una tarea GitHub, objetivos verificables y un conjunto de pruebas que GitHub Actions ejecuta en paralelo. La coordinación y evaluación de resultados sigue siendo supervisada en esta conversación; nadie está haciendo investigación en segundo plano por haber creado estos archivos.

## Líneas de trabajo

| Línea | Tarea | Alcance y criterio de progreso |
|---|---|---|
| **A. Bruce** | [#99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99) | Origen del bit 3 de **SRC_GPR7** en código firmado; distinguir literales, escrituras originales y alcanzabilidad |
| **B. Bootloader A** | [#100](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/100) | Entrada a actualización, validación HAB y recuperación IVT; evidencias de origen externo solo con cadenas reales |
| **C. NXP ROM/HAB** | [#101](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/101) | Versión real de HAB y aplicabilidad de avisos; sin atribuir explotación a una familia por proximidad |
| **D. USB / HID / BLE** | [#102](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/102) | Análisis pasivo URB/IRP y procedencia de peticiones; privacidad y trazas reales frente a hipótesis |
| **E. Auditoría independiente** | [#103](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/103) | Contrastar hashes, instrucciones originales, afirmaciones y pruebas; decidir GO/NO-GO |

## Hallazgo crítico que unificamos

Según el mapa de registros del **i.MX RT1060**, `0x400F8038` es **SRC_GPR7**, mientras `0x400F8034` es SRC_GPR6. La denominación antigua de GPR6 se ha corregido en las ramas **#96 y #98**. La rama **#97** queda **superada y no debe integrarse** con su identificación antigua. La dirección MMIO y la máscara de bit `0x08` son las originales; **no se conoce todavía el escritor efectivo de dicho bit ni control desde USB**.

La aplicación Bruce firmada contiene una instrucción `STR` cuyo destino calculado es SRC_GPR7 y que almacena **5 o 6**; estos valores no activan el bit 3. Se debe distinguir esto de cualquier afirmación sobre recuperación, ejecución o vulnerabilidad.

## Protocolo de aportaciones

Cada conclusión debe decir si procede de **medición física**, **binario OEM verificado por SHA-256**, **conjunto parcial de instrucciones previamente extraídas**, **prueba sintética** o **hipótesis**. Cada PR debe aportar una reproducción automatizada y un criterio de avance claro. No se consideran hallazgos reales los caminos de emulación que no llegan a hardware.

La [CI de líneas paralelas](../../.github/workflows/research-workstreams.yml) ejecuta matrices de pruebas sintéticas independientes para A–E; esto no equivale a desplegar LLMs ni a activar trabajos persistentes en segundo plano. La [CI principal](../../.github/workflows/offline-research.yml) mantiene Python 3.11/3.12 y la [auditoría de originales](../../.github/workflows/nxp-rom-advisories-phase81.yml) valida archivos OEM públicos por SHA-256.

## Nuevas prioridades después de la fase 90 (27-10-2026)

Los cinco ámbitos originales siguen vigentes, pero se añaden tres tareas subordinadas de investigación que **no son agentes autónomos activos**:

- **Gotham/Wi-Fi local:** [#107](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/107) — obtener un gist por revisión y hash, auditar BLE/credenciales y construir pruebas sintéticas sin tocar el mando. El script no está auditado todavía.
- **Recuperación Flash:** [#108](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/108) — estudiar offline la matriz de modos, FCB y posibilidad real de recuperación. Las herramientas de Gary escriben registros FlexSPI incluso cuando extraen flash: no realizarlo en el único mando.
- **NCC/NXP HAB:** [#109](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/109) — comprobar precondiciones de la vulnerabilidad DCD/CSF y versión ROM; no atribuir el exploit de i.MX6ULL a Stadia sin pruebas.

La [auditoría de fase 90](investigaciones-externas-fase90.md) y su [CI con tres comprobaciones](../../.github/workflows/external-research-phase90.yml) fijan los límites. GitHub Actions verifica fuentes públicas y pruebas sintéticas, **no ejecuta investigación autónoma persistente**.

## Política de riesgo

- Sin escribir flash/IVT, registros físicos o eFuses en el único mando; sin inyección de fallos ni cortes de alimentación.
- No subir el bootloader privado, datos identificativos ni cargas útiles USB.
- **HAB CLOSED permanece activo; no hay código propio ejecutado ni firmware modificado instalable demostrado.**
- El hallazgo de un escritor GPR7 desde USB, si ocurre, **no elimina** la autenticación obligatoria del firmware.
- Las tareas abiertas son **planes de trabajo**, no procesos autónomos que estén avanzando sin la intervención del usuario.

## Integración de ramas

La consolidación integra desde la base principal actual las investigaciones [#81](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/81) → [#82](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/82) (USB pasivo) y [#90](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/90) → [#96](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/96) → [#98](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/98) (HAB/bootloader corregidos). Se conservan los cambios físicos HID ya publicados en `main`. Se excluye deliberadamente #97 por conflicto conceptual. La integración solo pasa a `main` cuando GitHub Actions termina correctamente y se confirma la fusión.
