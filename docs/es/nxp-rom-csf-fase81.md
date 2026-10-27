# Fase 81 — Revisión NXP HAB ROM, CSF y CVE-2022-45163 (sin mando)

**27 de octubre de 2026.** Investigación de solo lectura sobre archivos originales verificados por hash. No se ha accedido al mando, probado una petición SDP, escrito firmware ni cambiado fusibles.

## Dos avisos distintos, dos consecuencias distintas

**1. Vulnerabilidad de autenticación HABv4 al extender la raíz de confianza.** [NXP confirma](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348) afectación a versiones HAB hasta **4.3.6** cuando software posterior llama a la API ROM para autenticar imágenes *adicionales*. NXP aclara que no afecta al arranque primario en general. [AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) recomienda comprobar los punteros DCD y los comandos CSF antes de esa autenticación.

**2. [CVE-2022-45163: SDP Read Bypass](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565).** NXP incluye **todas las revisiones i.MX RT105x/106x** en su aviso. Su impacto documentado es **divulgación potencial de memoria**, no ejecución autenticada de firmware propio. La recomendación oficial de deshabilitar SDP mediante eFuse es irreversible y queda fuera del alcance.

## Comparación con nuestro Stadia

- **Medición real, 25/10/2026:** identificador de MCU `0x006C0000` (la herramienta lo etiqueta 106XA0); ROM SDP `1FC9:0135`; respuesta de estado `0x12343412` (**HAB CLOSED**). [Mediciones](mediciones.md) · [Evidencia ROM](../../evidence/rom-status.json). No se extrajo ni identificó la **versión HAB de la BootROM**.
- **Código firmado del bootloader A:** ruta de autenticación secundaria `0x60801F5C` → tabla ROM RVT `0x0020032C` (**`authenticate_image_no_dcd`**). La variante evita ejecutar DCD durante *esa llamada*. **No prueba que el parser CSF antiguo esté parcheado**, ni que otro mecanismo ROM no procese DCD. [Análisis](arranque.md).
- **Firmas OEM:** ya se verificaron matemáticamente certificados CMS y hashes de las imágenes originales. Esa comprobación no acredita el valor SRK programado ni el comportamiento de ROM ante archivos malformados. [Auditoría de autenticación](decision-final-ejecucion.md).

## Herramienta de fase 81

El nuevo [auditor offline](../../tools/audit_nxp_rom_advisories_phase81.py) comprueba *tamaño y SHA-256 íntegros* antes de inspeccionar tres muestras originales: bootloader A extraído (**privado**), aplicación Bruce firmada y cargador RAM firmado (**archivados públicamente**). Recorre el IVT y sus comandos CSF de longitud declarada, sin buscar bytes arbitrarios que producirían falsos positivos. Detecta:

- `WRITE_DATA` — tag `0xCC`.
- `CHECK_DATA` — tag `0xCF`.
- `SET MID` — tag `0xB1` con parámetro `0x01`.
- Comandos desconocidos y delimitaciones malformadas.

La clasificación sigue las [cabeceras HAB de U-Boot](https://nest-open-source.googlesource.com/manifest_repos/u-boot/+/06419a4bae2adcdd0ed4e73f93f3f40a82172e45/arch/arm/include/asm/mach-imx/hab.h) y sus [comprobaciones explícitas de comandos obsoletos](https://qemu.googlesource.com/u-boot/+/bef9fdbed2e525ce9264d2ae2fbcb37db7472052/arch/arm/mach-imx/hab.c).

La [CI dedicada](../../.github/workflows/nxp-rom-advisories-phase81.yml) descarga **temporalmente solo** Bruce y el cargador RAM, confirma sus hashes SHA-256, ejecuta la auditoría y elimina los archivos. El bootloader A no se publica. Las [pruebas sintéticas](../../tests/test_nxp_rom_advisories_phase81.py) verifican que el analizador rechaza muestras alteradas, comandos truncados y longitudes incorrectas.

```sh
python -m unittest tests/test_nxp_rom_advisories_phase81.py -v
python -m tools.audit_nxp_rom_advisories_phase81 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod --out local/bruce-csf.json
python -m tools.audit_nxp_rom_advisories_phase81 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader --out local/loader-csf.json
python -m tools.audit_nxp_rom_advisories_phase81 local/bootloader-a.bin --sample bootloader_a --out local/bootloader-csf.json
```

## Evidencia que falta

**Encontrar cero comandos antiguos en la imagen OEM original no prueba que la ROM rechace una imagen manipulada.** La vulnerabilidad investigada se refiere precisamente a validaciones de imágenes adicionales no confiables. La herramienta **no emula la ROM ni prueba vulnerabilidades**. Hay que identificar de forma independiente la versión HAB y las validaciones ROM efectivas.

La vía SDP tiene otro objetivo técnico: posible lectura de memoria. **No se puede deducir de ella ejecución de código propio, bypass HAB ni soporte directo para Xbox/Switch 2.** No se propone ningún ensayo que pueda inutilizar el mando único ni modificar fusibles OTP.

**Regla de avance:** nueva evidencia independiente de ROM/HAB, o del receptor real que utilice la API para imágenes adicionales. Sin ello, mantener abiertas las hipótesis, pero **no tratarlas como desbloqueo demostrado**.
