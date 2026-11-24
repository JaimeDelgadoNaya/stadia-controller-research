# Fase 103 — Identidad y procedencia de la BootROM: rechazo de falsos positivos

**Fecha de verificación:** 24 de noviembre de 2026. Investigación *offline*. No hay acceso físico al mando, lectura interna, petición USB, SWD/JTAG, escritura de registros, cambios en flash ni eFuses.

## Resultado nuevo

El obstáculo crítico de las fases 94–102 no era encontrar otro archivo de 128 KiB: era demostrar que una imagen de 128 KiB **es realmente la máscara BootROM interna del silicio de nuestro Stadia**.

Se ha publicado un clasificador de evidencia que **rechaza** las copias de memoria SPI NOR externa y los archivos de procedencia no verificable, aunque tengan igual longitud o las mismas siete huellas de funciones de la ROM pública RT1060.

El controlador del usuario conserva las siguientes medidas del 25/10/2026, archivadas en [mediciones](mediciones.md) y [rom-status.json](../../evidence/rom-status.json):

- USB ROM SDP `1FC9:0135` y `ERROR_STATUS=0x12343412` → HAB **CLOSED**, no HAB abierto.
- `DIGPROG=0x006C0000` → familia RT106x; [NXP indica expresamente que no identifica la variante RT1061/RT1062](https://community.nxp.com/t5/i-MX-Processors/Device-Identification-Register/td-p/1528156).
- Bootloader OEM A, **flash externa** en `0x60800000`, de **131072 bytes**, SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
- Bootloader B, espacio externo `0x60820000`, de **131072 bytes y todo `FF`**, SHA-256 `b5a41c3758763bbec72769fab4a2533bf2db0b6312d93d25a695f9e4b9e02260`.
- Ninguno de los dos archivos es la ROM interna `0x00200000–0x0021FFFF`.

## Hallazgo bibliográfico importante: el titular «ROM dump» puede inducir a error

El artículo [*Taking a Google Stadia Controller Apart and Dumping its ROM*, 7 abril 2021](https://blog.lidskialf.net/2021/04/07/taking-a-google-stadia-controller-apart-and-dumping-its-rom/) indica que su autor desoldó una memoria **Zetta 25LQ128 SPI NOR** y leyó su contenido con flashrom. Describe la cabecera `FCFB` (FlexSPI NOR configuration) y código de aplicación desde `0x60801000`. **No es un dump de la ROM de máscara del RT1061**, a pesar del título. Nuestro verificador rechaza `FCFB` como fuente de BootROM interna.

La BootROM pública usada para el análisis previo procede de `Zenofex/SoC-BootROMs/nxp/imxrt1060.bootrom.bin`, tamaño 131072 y SHA-256 `a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e`. Su código de MPU/HID fue verificado en fase 98 y parcialmente emulado en fase 100. Esa referencia **no tiene ninguna cadena de procedencia con la unidad del propietario**.

## Información de máscara/silicio: necesaria, pero insuficiente

NXP documenta dos masksets `0N00X` y `1N00X` para RT106x, con versión B y corrección de la errata USB de conflictos de endpoints `ERR050101`: [PCN oficial 202007035F01U01](https://www.nxp.com/pcn/202007035F01U01). Esto confirma que **no** debemos asumir el mismo silicio/ROM por compartir la identificación de familia; tampoco implica que cada ROM sea distinta byte a byte ni cuál equipa nuestro mando. Una marca de chip, incluso `0N00X`/`1N00X`, **no sustituye una huella interna**.

El documento aportado `debug-connector.md` mapea UART y SWD y afirma que el autor no consiguió una conexión SWD fiable por las pistas del conector Hirose, aunque observó puntos de test separados. La existencia de pines SWD **no significa que el acceso de depuración esté abierto**. [NXP AN12419](https://www.nxp.com/docs/en/application-note/AN12419.pdf) describe seguridad Secure JTAG y fusibles que pueden restringir el acceso. No recomendamos conexiones, fusión ni intervención física en la unidad del usuario en esta fase.

## Verificador negativo desarrollado

### Archivos

- [Herramienta](../../research/phase103/triage_rom_origin.py)
- [16 tests](../../tests/test_rom_provenance_phase103.py)
- [CI reproducible](../../.github/workflows/phase103-rom-provenance.yml)
- [Evidencia no sensible](../../evidence/rom-provenance-phase103.json)

### Entradas

- `--candidate`: imagen binaria local de origen **supuesto** interno, de 131072 bytes.
- `--reference`: referencia pública RT1060, exigida por SHA-256.
- `--manifest`: declaración externa opcional del origen. **El manifiesto no certifica por sí mismo la procedencia.**

No hay dependencias de USB, SDP, MCU, JTAG, red ni firmware OEM. El resultado siempre fuerza `physical_origin_authenticated=false`, `stadia_internal_rom_identified=false`, `safe_for_automatic_exploit_claim=false` hasta tener verificación independiente de procedencia.

### Pruebas de falsos positivos

| Caso probado | Resultado |
|---|---|
| Sin archivo candidato de ROM interna | `CANDIDATE_MISSING` |
| Imagen que no mide 128 KiB | `REJECT_WRONG_SIZE` |
| 128 KiB de `FF` (igual al bootloader B del propietario) | `REJECT_KNOWN_EXTERNAL_FLASH` |
| Imagen con cabecera `FCFB` | `REJECT_FLEXSPI_NOR_HEADER` |
| Imagen con IVT típico de bootloader firmado | `SUSPECT_BOOT_IMAGE_IVT` |
| Archivo hipotético con manifest que declara «BootROM» | `UNVERIFIED_INTERNAL_ROM_DECLARATION` |
| Imagen *idéntica byte a byte* a la ROM **pública** RT1060 | `PUBLIC_RT1060_BYTES_NOT_DEVICE_PROVENANCE` |
| Imagen alterada en un byte pero con las **7 regiones de 64 bytes** todavía idénticas | `ONLY_REFERENCE_WINDOWS_MATCH` |

Así se demuestra por qué **ni un hash público idéntico ni siete funciones coincidentes autentican por sí solos el origen en nuestro Stadia**. La prueba de windows se ejecutó sobre la referencia RT1060 pública modificando un byte fuera de las regiones; no es un dump alternativo real.

[GitHub Actions fase 103, final SUCCESS](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45381425674): **16/16 tests unitarios y cuatro escenarios con la referencia pública cuya SHA fue comprobada previamente**. No se ha conectado el mando.

## Siguiente criterio de avance útil

1. **Prioridad alta:** publicación de un port Stadia/Zephyr con archivo, placa, mapa de memoria y comportamiento ROMC reproducible; `tchebb` afirma disponer de uno, pero no hay publicación pública verificable al corte. [Declaración original](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/).
2. **Identificación independiente del maskset** de la unidad sin inferirlo de `DIGPROG` ni de las copias de la flash externa. La etiqueta de chip no garantiza equivalencia interna.
3. **Rom interna auténtica de procedencia documentada** (por propietario o investigador con método reproducible) y una comparación funcional con el código público RT1060. Sin esa evidencia, no cambiar el perfil «Stadia observado» del simulador.
4. **No ejecutar `--permanent`, FIELD_RETURN ni otros eFuses.** Ni siquiera la coincidencia completa autoriza a intentar un bypass en el único mando.

**Conclusión:** fase 103 cierra falsos caminos de identificación. No añade una prueba de ejecución de firmware propio en hardware ni demuestra la aplicabilidad de la vulnerabilidad al Stadia del propietario.
