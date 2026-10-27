# Fase 86 — Transacción de actualización del bootloader A: autenticación, escritura y recuperación

**27 de octubre de 2026.** Investigación offline y de solo lectura sobre las **instrucciones seleccionadas ya publicadas** del bootloader A (build **169429**, SHA-256 atribuido a la extracción del propietario `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`). No se disponía del archivo privado completo en esta sesión, por lo que **la auditoría valida bytes de las instrucciones publicadas y sus saltos, pero no calcula de nuevo el SHA-256 del fichero completo**. [Fuente](../../evidence/bootloader-analysis.json) · [Código](../../tools/audit_bootloader_update_transaction_phase86.py).

## Hallazgo principal

**El flujo OEM intenta instalar el IVT candidato de 4096 bytes antes de la autenticación HAB final del candidato.** Esta secuencia **no autoriza la ejecución de un firmware sin firma**: la función llama posteriormente a `authenticate_image_no_dcd`, y la selección de aplicación de arranque contiene otra validación antes de transferir PC al reset handler.

La distinción respecto a la prevalidación es esencial: `0x608020A8` permite seleccionar una comprobación **solo estructural** con `r1=0`; `r1=1` fuerza el camino hacia la autenticación HAB. Es un flujo de actualización con **instalación previa y comprobación posterior**, no un «modo developer» que desactive HAB CLOSED.

## Orden documentado, con anclajes originales

| Momento | Instrucciones OEM seleccionadas | Condición |
|---|---|---|
| Autenticar bootloader actual | `0x60801E00–02` | `r1=1`; abortar si falla |
| Prevalidar estructura del candidato | `0x60801E26–28` | `r1=0` después de éxito previo |
| Guardar IVT actual | `0x60801E36–48` | Copia de `0x1000` bytes; abortar si falla |
| Comprobar alimentación/entrada | `0x60801E54–5C` | Callback OEM original; abortar si falla |
| Leer IVT candidato | `0x60801E62 → 0x60801D9C` | Lectura de `0x1000`; error `0x0A` antes de escribir |
| Intentar instalar IVT candidato | `0x60801DC0 → 0x60801D40` | Escritura de `0x1000` mediante tabla de almacenamiento condicionada |
| Autenticar candidato tras intento de escritura | `0x60801E80–8C` | `r1=1`; éxito local si devuelve cero |
| Intentar restaurar IVT guardado | `0x60801E9A–A6` | En rutas de fallo de escritura/autenticación; puede fallar |

El descriptor de almacenamiento `0x12` corresponde al IVT compartido en flash `0x60001000`, según [fase 11](almacenamiento.md) y la [ruta condicional al escritor](ruta-escritura.md). La escritura de este IVT **no prueba la programación de una aplicación ejecutable**, ni tampoco el éxito de un comando enviado desde USB.

## Modos de fallo y ventana temporal

La [herramienta](../../tools/audit_bootloader_update_transaction_phase86.py) verifica bytes, opcodes y destinos de **31 instrucciones ancladas**. Utiliza el auditor preexistente [trace_write_path.py](../../tools/trace_write_path.py) para exigir consistencia de las regiones de instrucciones y tablas de almacenamiento. Después recorre **256 combinaciones sintéticas** de ocho resultados de comprobaciones y modela estos casos:

- Fallo inicial HAB, de estructura, de lectura de copia o de alimentación: **sin intento de instalar IVT**.
- Fallo de lectura del IVT candidato (`0x0A`): **sin escritura de IVT candidato ni restauración**.
- Error tras intentar escribir el candidato: **intento de restauración**; la escritura podría haberse realizado parcialmente, pero no se ha medido.
- Error en autenticación HAB posterior: **intento de restauración**.
- Autenticación posterior satisfactoria: finalización local, **sin implicar que un firmware propio arranque**.

**La vulnerabilidad principal que merece vigilancia aquí es de fiabilidad y recuperación:** si se interrumpe la alimentación después de modificar el IVT pero antes de autenticar/restaurar, el flujo no ofrece en las instrucciones auditadas una garantía de atomicidad. Que la restauración aparezca en código **no la hace infalible**, y en el mando medido el bootloader B estaba borrado (`0xFF`), sin respaldo operativo demostrado.

**Esta secuencia no es una prueba de elusión de firmas**. Un IVT temporalmente escrito, o una prevalidación estructural superada, no demuestra acceso USB al flujo, salto a la app sin HAB, recuperación después de un corte ni que podamos instalar un firmware alternativo.

## Decisión GO/NO-GO

**NO-GO** para probar escrituras de flash, peticiones malformadas, modificar el IVT o intentar «aprovechar» la ventana en el único mando disponible.

**GO** para estudiar en modo offline la procedencia de los parámetros de actualización y los guardas del escritor físico, buscando **una entrada externa controlable con prueba independiente** y un plan seguro de recuperación. Sin esa evidencia y sin un segundo dispositivo recuperable, no tiene sentido ensayar la modificación.

La versión HAB real de la ROM sigue sin medirse, y [CVE-2022-45163](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565) sigue siendo una posible vía de divulgación de memoria, no una ejecución de código propia demostrada.

## Reproducibilidad

```sh
python -m unittest tests/test_bootloader_update_transaction_phase86.py -v
python -m tools.audit_bootloader_update_transaction_phase86 --out local/bootloader-transaction-phase86.json
```

[Pruebas](../../tests/test_bootloader_update_transaction_phase86.py) · [Evidencia de fase 86](../../evidence/bootloader-update-transaction-phase86.json) · [Resultados CI de fase 86](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/95).

**Límites:** pruebas sintéticas y registros públicos seleccionados, no emulación completa de flash, ROM ni hardware. No se ha conectado el mando ni escrito RAM, flash o eFuses.
