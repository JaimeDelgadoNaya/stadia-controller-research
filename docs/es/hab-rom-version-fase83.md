# Fase 83 — Procedencia de la versión HAB en BootROM RT1060

**27/10/2026. Estado: versión exacta no medida.** Esta fase convierte una hipótesis de vulnerabilidad de NXP en una cadena de evidencia comprobable **sin conectar el mando**. No envía comandos USB, no llama a BootROM, no modifica flash/RAM ni eFuses.

## Hallazgo en documentación original

1. El **Manual de referencia del RT1060** y [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf), tablas 2, 3 y 5, sitúan la *ROM Vector Table* (RVT) de HABv4 en **`0x00200300`**. Son *direcciones de slots de punteros*, no direcciones directas de funciones:
   - `authenticate_image_no_dcd`: offset `+0x2C` = **`0x0020032C`**.
   - `get_version`: offset `+0x30` = **`0x00200330`**.
2. El [manual oficial HABv4 API](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/MCX/481/1/HAB4_API.pdf) especifica cabecera RVT con etiqueta **`0xDD`**, longitud y byte de versión, y una función **`uint32_t get_version(void)`** cuyo resultado representa la versión de la biblioteca HAB de la ROM.
3. **Precaución:** [NXP AN12263, limitaciones](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) señala que **HAB 4.2.7** no admite las funciones `get_version()` y `authenticate_image_no_dcd()` como cabría esperar. Para un equipo específico hay que verificar la tabla real y el retorno; ni el nombre de la familia ni la cabecera de una imagen bastan.
4. El [aviso NXP sobre autenticación de imágenes adicionales](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348) indica afectación de HAB **hasta 4.3.6**, *solo cuando se usa la API de ROM para autenticar imágenes adicionales*. La versión es condición necesaria de clasificación, **no prueba de un bypass explotable**.

## Qué prueba y qué no el repositorio

| Fuente | Evidencia real | ¿Demuestra versión HAB ROM exacta? |
|---|---|---|
| [Estado ROM real](../../evidence/rom-status.json) | `0x12343412` = HAB CLOSED, `0xF0F0F0F0` = Success | **No** |
| [Bootloader A firmado](arranque.md) | Llama a `0x0020032C` mediante la rutina OEM `0x60801F5C` | **No** |
| IVT de las imágenes OEM | Byte de cabecera de formato del archivo | **No** |
| CSF de las imágenes OEM | Byte de cabecera de formato de los comandos | **No** |
| *Lectura ROM* de la RVT `0x00200300` | **Todavía no existe** para la unidad | Podría establecer slots y cabecera, no necesariamente patch |
| Valor devuelto de `get_version()` en esa ROM | **Todavía no existe** | Sería la evidencia específica buscada |

El valor **`0x41` de la cabecera IVT** y el posible **`0x42` del CSF** representan **versión de formato de estructura**, **no** HAB 4.1/4.2 del silicio ni mucho menos su versión 4.3.6/4.3.7. La herramienta comprueba estos bytes contra las imágenes OEM con SHA-256 antes de emitir resultados; la CI determina y registra los valores reales.

## Herramienta y límites

[Analizador offline](../../tools/audit_hab_rom_version_phase83.py) · [pruebas sintéticas](../../tests/test_hab_rom_version_phase83.py)

El analizador:
- Comprueba identidad de imagen original usando el detector **SHA-256 de fase 81**.
- Registra los bytes de cabecera IVT/CSF en **su categoría correcta**, separados de la versión HAB de la ROM.
- Permite analizar **opcionalmente** una tabla RVT previamente adquirida por el propietario (hasta 256 bytes), exige etiqueta `0xDD` y límites coherentes; clasifica los punteros en `+0x2C/+0x30`, **sin ejecutarlos**.
- Puede incorporar un retorno numérico que alguien haya obtenido por otra vía, siempre etiquetándolo **«proporcionado por operador, no verificado independientemente»**. No interpreta como demostrada la revisión HAB ni la vulnerabilidad.
- Es explícito: las pruebas usan bytes sintéticos; un snapshot proporcionado no autentica por sí mismo la identidad del mando.

Ejemplo sin hardware con un archivo OEM local legítimo:

```sh
python -m unittest tests/test_hab_rom_version_phase83.py -v
python -m tools.audit_hab_rom_version_phase83 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader --out local/hab-phase83.json
python -m tools.audit_hab_rom_version_phase83 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod --out local/hab-bruce-phase83.json
```

## Decisión

**Resultado actual: no hay versión HAB ROM exacta demostrada; no se puede confirmar la aplicabilidad de la vulnerabilidad de autenticación en la unidad.** [CVE-2022-45163](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565) describe una **superficie SDP de confidencialidad distinta**, no desbloqueo de firmas.

Próximo criterio de avance: evidencia independente y segura de tabla/versión ROM y verificación de cómo el bootloader maneja las imágenes adicionales. No se propone conectar el mando ni ejecutar código de prueba, explotar fallos o cambiar fusibles.
