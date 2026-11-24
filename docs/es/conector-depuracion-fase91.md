# Fase 91 — Conector de depuración UART/SWD del mando Stadia: evaluación documental

**23/11/2026. Evidencia externa aportada por el propietario, no medida en su unidad.** Esta fase incorpora un pinout atribuido a un archivo entregado en la conversación, `debug-connector.md`. **No** se ha conectado una sonda al mando, capturado UART, abierto una sesión SWD, leído memoria, grabado flash, cambiado OTP ni ejecutado firmware propio.

## Aporte del documento recibido

El texto sitúa un conector de depuración no poblado de **17 contactos**, frente al conector de panel frontal, y comunica compatibilidad física con **Hirose FH35C-17S-0.3SHW**. La numeración **no es un estándar oficial**: siguiendo el esquema del artículo de [adq (2021)](https://blog.lidskialf.net/2021/04/07/taking-a-google-stadia-controller-apart-and-dumping-its-rom/), una hilera es `1…9` y la otra `A…H`; **no inferir orientación/pines físicos solo de esta lista**, porque un cable puede invertir el orden. La tabla siguiente se reproduce como *reporte externo*, no como medición realizada por nosotros.

| Contacto | Señal descrita | Observación atribuida al documento |
|---|---|---|
| 4 / D | LPUART1 TX / RX | El autor declara contacto UART fiable con sondas PCBite |
| 5 / 7 | SWCLK / SWDIO | En el conector de 17 pads, el autor no consiguió sesión SWD estable |
| 6 | SWO | Bajo con pulsos transitorios descritos al encender/apagar |
| F | nRESET | Reset del SoC activo en bajo |
| H | Vdd | 3,3 V **suministrados por la placa**; no inyectar alimentación |
| E / G / 9 | GND | Referencias de masa |
| 2 | nPWR | Botón Stadia activo en bajo |
| 1 / A / B / 3 / C / 8 | NC | Sin conexión según el autor |

El autor también identifica **cuatro puntos de prueba en vertical cerca del gatillo izquierdo**, ordenados de arriba abajo: `SWDIO/TMS`, `SWCLK/TCK`, `SWO/TDO`, `TDI` (TDI no se usa en SWD). Los describe como más accesibles para sondas que el conector de 17 contactos. **El texto no documenta ninguna lectura satisfactoria por SWD ni un acceso desbloqueado a la depuración.**

[Mapa estructurado, con procedencia y límites](../../evidence/debug-connector-phase91.json).

## Contraste con la seguridad conocida

- **Plano físico:** las pistas de UART/SWD podrían permitir instrumentación, pero continuidad eléctrica o señales oscilando no equivalen a capacidad de depuración. UART transmitido no implica consola ni comandos de entrada.
- **Plano del sistema de seguridad:** NXP documenta control de acceso de depuración mediante *System JTAG Controller*, fusibles y modos seguros. Véase [NXP: RT106X secure JTAG test and IDE debug](https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs-Knowledge/RT106X-secure-JTAG-test-and-IDE-debug/ta-p/1685577) y [SJC_DISABLE blocking flashing over SWD](https://community.nxp.com/t5/i-MX-Processors/SJC-DISABLE-blocking-flashing-over-SWD/m-p/2008922). El estado **HAB CLOSED** constatado anteriormente en la unidad del propietario **no determina por sí solo** su configuración de acceso SWD/SJC.
- **Plano de ejecución:** el [gate documentado de fase 31](../en/final-execution-recovery-decision.md) sigue vigente: el autor del proyecto no dispone de ejecución propia autorizada ni de restauración de firmware robusta. Un pinout no invalida las firmas HAB ni la evidencia criptográfica.
- **Aplicación a #99 y #100:** las dudas sobre el escritor de `SRC_GPR7 bit 3` y la procedencia de la orden de actualización del bootloader **no quedan resueltas** por estos puntos de contacto. Solo podría surgir evidencia adicional si hubiera acceso verificado y mediciones controladas, ausentes aquí.

## Nueva información externa de noviembre de 2026, por separado

En una [conversación pública de r/Stadia](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) el usuario `tchebb` dice haber publicado el proyecto [`nxp-sdp-overrun`](https://codeberg.org/tchebb/nxp-sdp-overrun) y haber ejecutado firmware propio de Zephyr en su mando. Es una **declaración de tercero**. El repositorio de Codeberg **no se pudo inspeccionar ni descargar en esta sesión**; el payload, revisión, aplicabilidad al RT1061, persistencia, protección de OTP y recuperación **no han sido auditados aquí**. Su afirmación no demuestra que el mando del propietario esté desbloqueado ni cambia el **NO-GO físico** hasta verificación independiente.

## Decisión y siguiente investigación

**GO**: documentar pinout atribuido, validar coherencia y procedencia de cada señal, contrastar la estructura del SoC y el control SJC con fuentes NXP, y estudiar de forma **offline** cualquier código original y evidencia reproducible que se publique de `nxp-sdp-overrun`.

**NO-GO**: abrir o soldar el mando único, alimentar por Vdd de sonda, forzar reset/nPWR, conectar hardware de escritura, flashear un bootloader alterado, modificar `FIELD_RETURN`/fusibles, ni presentar UART/SWD como desbloqueo demostrado.

**Criterios de reapertura de la línea física:** identificación independiente de la revisión de PCB y orientación de conector, confirmación de pinout y niveles sin inyección de energía, permisos de depuración constatados, estrategia de copia/restauración reproducible en unidad de repuesto recuperable, y auditoría separada del supuesto exploit.

Enlace a contexto: [fase 90, auditoría de fuentes externas](investigaciones-externas-fase90.md), [issue #99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99) y [issue #100](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/100).
