# Fase 92 — Evaluación de exploit SDP y límites de transferencia al Stadia

**23/11/2026. Investigación documental y estática, sin dispositivo conectado.**

## Hallazgo de noviembre 2026: vulnerabilidad de U-Boot SPL

El 4 de noviembre de 2026, Ana Bobillo publicó en la lista U-Boot el parche `[PATCH 0/6] usb: gadget: f_sdp: honour a closed i.MX part, bound ep0 data`:
https://lore-kernel.gnuweeb.org/u-boot/179492784365.252888.14543908917482879599.b4-review%40b4/T/

La descripción atribuye a **U-Boot SPL con SPL_USB_SDP_SUPPORT** una aceptación de saltos/lecturas/escrituras SDP sin las restricciones apropiadas para un dispositivo HAB CLOSED. El análisis de Torizon del 6/11/2026 informa de una reproducción en plataformas Toradex y del efecto de aplicar el parche:
https://www.torizon.io/blog/fixing-a-10-year-old-early-vulnerability-on-nxp-processors

**No es una vulnerabilidad de BootROM NXP**: depende de que el dispositivo ejecute U-Boot SPL vulnerable y exponga esa segunda implementación SDP. No existe evidencia de que el Stadia Controller RT1061 ejecute ese componente. **Transferibilidad al mando: NO DEMOSTRADA.** No asociar el parche de U-Boot con el proyecto de tchebb sin una cadena de procedencia explícita.

## `nxp-sdp-overrun` (tchebb): estado de procedencia

URL declarada: https://codeberg.org/tchebb/nxp-sdp-overrun

El repositorio no se pudo abrir mediante el acceso web disponible; tampoco se pudo clonar desde el entorno local (sin resolución DNS). Por tanto:
- no existe árbol de fuentes, commit, hash ni binario autenticado en esta fase;
- no se ha podido revisar un payload, compilación, compatibilidad RT1061, ni un resultado de ejecución;
- cualquier afirmación de ejecución Zephyr en Stadia es **reporte externo no reproducido**, no conclusión de esta investigación.

**Criterio de admisión:** conseguir un archivo fuente original o tarball verificable, fijar commit y hashes, revisar código y licencias offline, modelar flujo de memoria y recuperación, y separar ejecución temporal en RAM de escritura persistente y bypass HAB.

## CVE-2022-45163: categoría distinta

CVE-2022-45163 incluye expresamente i.MX RT1060 y describe una **divulgación de memoria en SDP** de dispositivos de arranque seguro; por sí sola no prueba ejecución de código sin firma:
https://cve.circl.lu/vuln/gsd-2022-45163

La investigación del repositorio ya había clasificado esta CVE en fase 81. No debe fusionarse con la vulnerabilidad U-Boot SPL 2026 ni atribuirle capacidades adicionales.

## Puente con el conector SWD (fase 91)

El pinout de UART/SWD es un reporte externo, no una sesión de depuración demostrada. El manual RT1060 documenta fusibles `SJC_DISABLE`, `JTAG_SMODE` y `DAP_SJC_SWD_SEL`; HAB CLOSED no fija por sí solo los tres valores:
https://www.pjrc.com/teensy/IMXRT1060RM_rev1.pdf

**Decisión:** continuar únicamente con auditoría offline, manteniendo el NO-GO de escritura física, flash, OTP y explotación sobre el único mando. El objetivo final de emular un mando Xbox no exige demostrar un bypass: mantener la alternativa de puente externo como línea independiente.

## Estado y próximos criterios

| Hipótesis | Evidencia | Decisión |
|---|---|---|
| U-Boot SPL SDP 2026 permite saltos no autenticados en plataformas afectadas | Parche original + prueba externa Toradex | Confirmado en el contexto descrito, no extrapolable al Stadia |
| RT1061 Stadia ejecuta U-Boot SPL vulnerable | Ninguna | No demostrado |
| tchebb `nxp-sdp-overrun` permite código propio | URL externa, código no accesible | Pendiente de verificación |
| CVE-2022-45163 equivale a bypass de firma | Descripción oficial: divulgación de memoria | No |
| SWD físicamente expuesto equivale a SWD desbloqueado | Solo mapa externo | No |

No se ha realizado ningún experimento físico ni compilación del supuesto exploit.
