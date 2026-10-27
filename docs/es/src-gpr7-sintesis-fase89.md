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

## Nota documental de NXP: reserva no equivale a escritor

El [manual RT1060 Rev. 3, §21.6.11](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf) describe SRC_GPR7 en **0x400F8038**, con valor de reset documentado cero y reservado al uso de ROM. Sin embargo, [un empleado de NXP aclaró](https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs/SRC-GPRx-Register-Usage/m-p/1037773) que **la ROM actual no utiliza necesariamente todos los SRC_GPR** y que se reservan también por compatibilidad con otras versiones o procesadores. No hay un nombre de función ni una máscara documentada de propósito especial para GPR7 bit 3 en estas fuentes. El valor de reset publicado **no establece por sí solo el resultado tras cada clase de reinicio cálido**.

**Por tanto, ni la reserva de ROM ni la ausencia de MOVT demuestran quién escribe 0x08.**

## Clasificación del único MOVW encontrado

El contexto Thumb original firmado está en el offset **0x21E22** (XIP **0x60061E22**). La secuencia exacta de seis bytes **48f200007047** se decodifica:

```asm
0x60061E22  MOVW R0, #0x8000
0x60061E26  BX   LR
```

Las instrucciones próximas utilizan operaciones de coma flotante VABS/VCMP/VCVT. La pareja de instrucciones anterior prepara un **valor de retorno numérico**; **no carga la mitad alta de una dirección SRC ni realiza una escritura de GPR7**. La herramienta comprueba esos seis bytes sobre la imagen completa autenticada por SHA-256. La alcanzabilidad efectiva de la rutina no se ha observado.

## Decisión

**NO-GO para seguir buscando esta forma concreta MOVW/MOVT en los dos archivos firmados examinados.** El escritor original conocido de Bruce en 0x60078A28 almacena 5 o 6 en SRC_GPR7 y **no establece bit 3 (0x08)**. El bootloader A sí lee ese bit antes de la ruta de actualización, pero el escritor real y cualquier influencia USB siguen desconocidos.

La identificación de GPR7 como registro reservado al uso de ROM en el manual del i.MX RT1060 **no demuestra que la ROM establezca el bit**. La supervivencia del bit tras un reset también sigue sin medirse. HAB CLOSED continúa vigente; no hay ejecución de firmware propio ni bypass de firmas probado.

**Siguiente investigación acotada:** documentación oficial sobre propiedad de SRC_GPR7, modos de reinicio y servicios ROM. Sin activación física ni pruebas destructivas.

[Pruebas sintéticas](../../tests/test_src_gpr7_movw_movt_phase89.py) · [Evidencia estructurada](../../evidence/src-gpr7-synthesis-phase89.json) · [Tarea Bruce #99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99).
