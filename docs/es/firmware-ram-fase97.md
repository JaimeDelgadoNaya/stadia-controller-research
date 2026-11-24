# Fase 97 — Primera imagen ARM Thumb propia: ejecución aislada en RAM

**24/11/2026.** Esta fase se concentra en firmware personalizado **directamente en el Cortex-M7**. No se conecta el Stadia ni se ejecuta el exploit USB.

## Resultado nuevo

Se ha ensamblado y enlazado un programa independiente para `arm-none-eabi / Cortex-M7` con **Clang 17 + lld** y se ha convertido a una imagen binaria de **20 bytes**.

- SHA-256 `firmware.bin`: `68a75935017e47c373d2df0b9294c31781705894511bc62fea78b6a265806f38`.
- MSP del vector de arranque: `0x20010000`, ejemplo de memoria **ilustrativo, NO comprobado en Stadia**.
- Reset vector Thumb correcto: `0x20000009`.
- Secuencia ARM Thumb:
  ```asm
  20000008: movs r0, #0x5a
  2000000a: ldr  r1, [pc, #4] ; literal = 0x20000014
  2000000c: str  r0, [r1]    ; único acceso de escritura: RAM del demo
  2000000e: b    0x2000000e
  ```
- El intérprete sintético ejecutó exactamente esos pasos, dejó un marcador de valor `0x5A` en `0x20000014` y rechazó escrituras fuera del marcador, vectores incorrectos e instrucciones no reconocidas.
- **12 de 12 pruebas unitarias superadas localmente**. Hay un workflow dedicado para repetir la compilación desde fuentes y el test en GitHub Actions. La CI debe consultarse por separado: crear el workflow no equivale a comprobar su resultado.

### Corrección de arranque detectada durante la revisión

En Thumb, el símbolo declarado con `.thumb_func` ya tiene el bit bajo activo en sus referencias de dirección. Al añadir `+1` manualmente, el vector terminaba erróneamente en `0x2000000A` **par**. Se eliminó el segundo incremento y el binario compilado contiene `0x20000009`. El error está cubierto por test.

## Evidencia vs. capacidades pendientes

| Capa | Comprobación | Estado |
|---|---|---|
| Compilar código ARM Thumb propio | ELF/BIN para Cortex-M7 | **Sí, offline** |
| Tabla de vectores Thumb | MSP y dirección de Reset | **Sí, offline** |
| Simular ejecución del binario compilado | Marcador RAM tras cuatro instrucciones | **Sí, modelo** |
| Control de acceso del programa en el modelo | Solo una escritura a marcador | **Sí, modelo** |
| Identidad exacta de BootROM de nuestro Stadia | Comparación RT1061 con referencia RT1060 | **No disponible** |
| Bypass HAB temporal en un mando real | Observación independiente tras SDP | **No probado** |
| Arranque real del firmware propio | Lectura posterior del marcador por ruta confiable | **No probado** |
| Firmware permanente, controlador de entradas, Xbox | Driver/flash/boot autónomo | **No logrado** |

En el archivo original `nxp-sdp-overrun`, `hid.write()` satisfactorio **no equivale a ejecución demostrada del payload**. Incluso si se desbloquea HAB para un arranque, instalar una imagen persistente plantea requisitos nuevos de firma, recuperación y arranque. El ejemplo de fase 97 no incluye código para conectar, flashear, cambiar ROMC, modificar OCOTP o enviar SDP.

## Artefactos GitHub

- [Programa ARM Thumb](../../research/phase97/minimal_ram.S).
- [Linker solo RAM, ilustrativo](../../research/phase97/ram_only.ld).
- [Intérprete sintético restrictivo](../../research/phase97/simulate_ram.py).
- [Doce tests independientes de hardware](../../tests/test_ram_execution_phase97.py).
- [CI: compilación + comparación de hash + interpretación offline](../../.github/workflows/phase97-ram-execution.yml).

Los binarios compilados y la traza completa se distribuyeron al propietario como archivo de conversación independiente y **no se han subido al repositorio**.

## Contexto externo comprobado

`tchebb` reconoce en [r/Stadia](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) que ha avanzado con un port Zephyr y firmware personalizado para el mando, pero **aún no estaba listo para publicación**. La evaluación en fase 97 no encontró código público verificable de ese port. No confundir proyectos Zephyr para **Steam Controller 2** con Stadia.

**Decisión:** continuar con ROM/HAB de la unidad y evidencias de port específico RT1061, **sin** usar `--permanent`, `FIELD_RETURN`, OTP o escrituras de firmware en el único dispositivo.
