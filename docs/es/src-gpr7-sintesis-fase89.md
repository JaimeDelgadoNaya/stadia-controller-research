# Fase 89 — síntesis Thumb de direcciones SRC_GPR7

**27 de octubre de 2026.** Continuación de la [fase 88](src-gpr7-escritores-fase88.md). Investigación sin mando conectado ni escrituras.

## Objetivo y método

El [auditor de fase 89](../../tools/audit_src_gpr7_movw_movt_phase89.py) examina los originales firmados de Bruce y del cargador RAM, después de exigir SHA-256 exacto, IVT y CSF mediante el auditor de fase 81. Busca instrucciones Thumb-2 con codificaciones MOVW de mitades bajas 0x8000, 0x8034 o 0x8038, y MOVT de mitad alta 0x400F. Su combinación podría formar las direcciones 0x400F8000, SRC_GPR6 o SRC_GPR7. También busca formas STR próximas cuyo destino calculado pudiese ser SRC_GPR7, **0x400F8038**.

Las parejas deben compartir registro y estar separadas por un máximo de 96 bytes; el barrido de posibles stores permite otros 96 bytes. **Coincidencia de instrucciones no demuestra límites reales de código, registros vivos ni ejecución.** Se excluyen otros cálculos aritméticos de punteros, tablas indirectas, código relocalizado a RAM y el contenido interno de ROM.

## Resultado original verificado

[GitHub Actions: originales fijados por hash](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40583595092)

| Patrón Thumb buscado | Bruce firmado | Cargador RAM firmado |
|---|---:|---:|
| MOVW con mitad baja de una dirección SRC | **1** | **0** |
| MOVT con mitad alta 0x400F | **0** | **0** |
| Parejas MOVW/MOVT | **0** | **0** |
| STR a GPR7 derivados de esas parejas | **0** | **0** |

**118 pruebas sintéticas acumuladas NXP 81–89 superadas.** Han pasado también Python 3.11/3.12 y los cinco trabajos de validación en paralelo. Un MOVW aislado no construye por sí solo una dirección completa SRC.

## Decisión

**NO-GO para seguir buscando esta forma concreta MOVW/MOVT en los dos archivos firmados examinados.** El escritor original conocido de Bruce en 0x60078A28 almacena 5 o 6 en SRC_GPR7 y **no establece bit 3 (0x08)**. El bootloader A sí lee ese bit antes de la ruta de actualización, pero el escritor real y cualquier influencia USB siguen desconocidos.

La identificación de GPR7 como registro reservado al uso de ROM en el manual del i.MX RT1060 **no demuestra que la ROM establezca el bit**. La supervivencia del bit tras un reset también sigue sin medirse. HAB CLOSED continúa vigente; no hay ejecución de firmware propio ni bypass de firmas probado.

**Siguiente investigación acotada:** documentación oficial sobre propiedad de SRC_GPR7, modos de reinicio y servicios ROM. Sin activación física ni pruebas destructivas.

[Pruebas sintéticas](../../tests/test_src_gpr7_movw_movt_phase89.py) · [Evidencia estructurada](../../evidence/src-gpr7-synthesis-phase89.json) · [Tarea Bruce #99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99).
