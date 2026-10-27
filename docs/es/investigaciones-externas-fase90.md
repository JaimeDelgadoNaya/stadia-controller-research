# Fase 90 — Tres investigaciones externas aplicadas al mando Stadia

**Fecha: 27 de octubre de 2026.** Auditoría estática y de fuentes públicas. No se ha conectado el mando, ejecutado código externo ni enviado peticiones USB/BLE; no se han manejado credenciales ni imágenes de firmware privadas.

## 1. Recuperación de flash — GaryOderNichts (prioridad: alta para seguridad)

Fuente: [StadiaController](https://github.com/GaryOderNichts/StadiaController/tree/1396830b449eee10e4d4de047c8db75d503f4ba3/stadiatool) y [explicación del procedimiento](https://garyodernichts.blogspot.com/2023/01/looking-into-stadia-controller.html).

El [auditor](../../tools/audit_external_research_phase90.py) exige los **tres Git blobs exactos** en el commit publicado `1396830b449eee10e4d4de047c8db75d503f4ba3`:

| Archivo | Git blob SHA-1 esperado |
|---|---|
| `stadiatool/stadiatool.py` | `4044e32aab2ea9a849101b03ef841fe358225b3e` |
| `stadiatool/flashloader.py` | `60c693767e3f795c7489dd5d38895c9d564724e0` |
| `stadiatool/sdp.py` | `ff97d184ce4346e48b7457c5f3d772711cc9fa30` |

Estos archivos se inspeccionan como **texto Python validado por hash y analizado sintácticamente con `ast.parse`**. No se importan ni ejecutan. Se constata que:

- `dumpFlash` usa `flashRead32`, que **escribe registros FlexSPI** para emitir lecturas de datos y luego consulta el FIFO `0x402A8100`. `setupFlash` también reconfigura el hardware del cargador firmado. Por tanto, la extracción **no es pasiva**, aunque su objetivo final sea leer datos.
- `flashFirmware` contiene las operaciones `flash_erase_region` y `write_memory`, incluida la instalación del IVT en `0x60001000`. **La disponibilidad de estas operaciones no garantiza poder restaurar un mando bloqueado**: necesita llegar a ROM SDP / cargador firmado y disponer de una imagen correcta compatible.
- El comentario upstream llama **«GPR 6»** a `0x400F8038`. Según el mapa de registros del i.MX RT1060 ya contrastado, su nombre correcto es **SRC_GPR7**. No modificar el comportamiento de la herramienta a partir del texto de un comentario desactualizado.
- La [documentación original de la herramienta](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/README.md) advierte expresamente que un uso incorrecto **puede inutilizar el mando**. No se propone ejecutarla en el único dispositivo del propietario.

**Resultado:** podemos reutilizar el diseño de los comandos y crear un **modelo de recuperación offline**, pero no anunciar un plan físico seguro ni realizar dumps reales sin copia integral, dispositivo de respaldo y procedimiento recuperable.

## 2. NCC Group — DCD/CSF y HAB (prioridad: secundaria condicionada)

Fuente: [NCC Group, bypass HAB sobre i.MX6ULL](https://www.nccgroup.com/research/shining-new-light-on-an-old-rom-vulnerability-secure-boot-bypass-via-dcd-and-csf-tampering-on-nxp-imx-devices/) y [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf).

| Condición | Demostración externa | Evidencia actual en Stadia |
|---|---|---|
| Familia y ROM HAB | i.MX6ULL con HAB 4.2; versiones afectadas anteriores a 4.3.7 | i.MX RT1060; **versión HAB exacta no medida** |
| API DCD en la autenticación posterior | La ruta vulnerable llama a autenticación que puede procesar DCD | Bootloader A usa `authenticate_image_no_dcd`: **no hay DCD** en ese camino documentado |
| IVT/DCD en imágenes originales | Puede existir DCD manipulado | Bruce y cargador RAM originales tienen **DCD nulo**, verificado por SHA-256 |
| CSF peligroso | El trabajo externo también describe manipulación de CSF antes de autenticación | Los CSF originales **no tienen comandos WRITE/CHECK/SET MID deprecados**. Esto **no prueba** que una imagen modificada sea inocua o que ROM la procese |
| Memoria modificable/resultado de rechazo | Requiere efectos sobre un cargador ejecutable antes de fallar | No demostrados en el RT1060 concreto ni con este bootloader |
| Cadena de confianza | Prueba de concepto pública en otra placa | Nuestro mando permanece **HAB CLOSED**; sin firmware propio ejecutado |

**Conclusión:** **NO-GO** para trasladar sin más el exploit DCD de NCC Group. **GO documental** para estudiar ROM/CSF con pruebas de versión, políticas de escritura y flujo antes de autenticación. No se prepara ninguna carga ni prueba destructiva.

## 3. Gotham — Wi-Fi por BLE sin modificar firmware (prioridad: alta para nuevas funciones)

Fuentes públicas: [comunicación del 26 de octubre](https://www.reddit.com/r/Stadia/comments/1xfwq9w/stadia_controller_wifi_provisioning_python_script/) y [script enlazado](https://gist.github.com/supernielsen/6cb9215b21481baafe171d645542f40f).

El autor afirma haber completado el aprovisionamiento Wi-Fi de un mando con el firmware **Gotham** original usando BLE y un intercambio relacionado con `DeviceKey`, observando el estado `0x3C`. En los comentarios del **27 de octubre** afirma haber logrado una negociación TLS y aceptación de certificado, pero que aún no consigue completar los mensajes finales del protocolo.

**Límite decisivo:** esta fase **no ha podido recuperar e inspeccionar una revisión concreta del código de ese gist**; tampoco se ha observado tráfico de un mando real ni autenticado un servidor local. Son **resultados reportados por la comunidad**, no una integración verificada en nuestro repositorio.

Tampoco está demostrado que el mando particular del propietario ejecute Gotham en lugar de Bruce. Cambiar de firmware o recuperar Wi-Fi requiere condiciones adicionales y puede ser irreversible.

**Siguiente hito verificable:** obtener una revisión íntegra e identificada por hash del script, auditar estáticamente características BLE y protección de credenciales; modelar el intercambio con **claves y contraseñas sintéticas**. Después investigar qué mensajes son necesarios para servicios locales sin simular los servidores de Google como si ya funcionasen.

## Matriz de decisiones y prioridades

| Línea | Riesgo de falsos positivos | Siguiente entregable |
|---|---|---|
| Gotham/Wi-Fi | Alto hasta auditar el gist | Protocolo y trazas **sintéticas**, sin secretos |
| Recuperación flash | Alto si se confunde «dump» con operación pasiva | Matriz de modos/guardas, imagen y recuperación **sin ejecutar comandos** |
| HAB NCC | Alto sin versión ROM y rutas de CSF | Tabla de precondiciones y discrepancias; sin bypass supuesto |

[Herramienta reproducible](../../tools/audit_external_research_phase90.py) · [pruebas](../../tests/test_external_research_phase90.py) · [evidencia](../../evidence/external-research-phase90.json) · [workflow de tres comprobaciones independientes](../../.github/workflows/external-research-phase90.yml).

**Límite del objetivo:** ninguna de estas fuentes demuestra todavía modificación libre del firmware Stadia con el MCU original y HAB CLOSED. Mantener líneas de trabajo separadas; no denominar «agentes autónomos» a las comprobaciones de GitHub Actions.
