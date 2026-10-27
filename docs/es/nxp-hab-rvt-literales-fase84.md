# Línea NXP — fase 84: censo acotado de literales RVT HAB

**27 de octubre de 2026. Solo lectura, sin mando conectado.** Continúa la [fase NXP 83](hab-rom-version-fase83.md); el número de fase corresponde a esta línea de investigación y no debe confundirse con otras fases HID del repositorio.

## Pregunta

¿Los archivos OEM firmados originales contienen **constantes explícitas** para llamar a los slots de funciones HAB de BootROM, en especial la entrada `get_version` en `0x00200330`? ¿Podemos encontrar alguna evidencia adicional a las rutas del bootloader A ya documentadas en [fase 9](arranque.md)?

## Método verificable

La [herramienta](../../tools/audit_hab_rvt_literals_phase84.py) comprueba primero el **tamaño y el SHA-256 de la imagen original** por medio del auditor de fase 81. Solo después inspecciona las palabras de 32 bits little-endian en posiciones alineadas a 2 bytes del segmento **anterior al CSF**. Examina exclusivamente estas constantes ya documentadas:

| Valor | Significado documental |
|---|---|
| `0x00200300` | Base de tabla HAB RVT |
| `0x00200304` | Slot `entry` |
| `0x00200308` | Slot `exit` |
| `0x00200324` | Slot `report_status` |
| `0x0020032C` | Slot `authenticate_image_no_dcd` |
| `0x00200330` | Slot `get_version` |

Cada coincidencia publica su offset de archivo, valor y alineación (`4_byte` o `2_byte_only`). Su clasificación es explícitamente **`instruction_reference_confirmed=false`**: un patrón de cuatro bytes puede aparecer como dato, como parte de un pool de literales, por casualidad o nunca llegar a ejecutarse.

El barrido **no** sigue referencias de instrucciones `LDR [PC]`, ni detecta direcciones sintetizadas por `MOVW/MOVT`, sumas, tablas de punteros, saltos indirectos o instrucciones no alineadas a 2 bytes. **Cero coincidencias no prueba ausencia de llamadas a `get_version`.** Una coincidencia tampoco prueba que la llamada exista o que pueda dispararse desde USB. Se necesitan anclajes de instrucciones originales y un flujo de control verificable.

**Control externo ya conocido:** el [análisis original del bootloader A](arranque.md) identifica la rutina firmada `0x60801F5C` que usa HAB `entry`, `authenticate_image_no_dcd` y `exit`. El archivo extraído en privado **no se sube a GitHub** y no se le atribuyen cifras de la herramienta nueva sin ejecutarla sobre su SHA original.

## Reproducción

```sh
python -m unittest tests/test_hab_rvt_literals_phase84.py -v
python -m tools.audit_hab_rvt_literals_phase84 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod --out local/rvt-bruce.json
python -m tools.audit_hab_rvt_literals_phase84 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader --out local/rvt-loader.json
# Opcional, solo con copia privada real del propietario:
python -m tools.audit_hab_rvt_literals_phase84 local/bootloader-a.bin --sample bootloader_a --out local/rvt-bootloader.json
```

El [workflow offline](../../.github/workflows/nxp-rom-advisories-phase81.yml) descarga temporalmente dos muestras públicas, comprueba los SHA-256 originales, ejecuta el censo y borra los archivos sin publicarlos. Las [pruebas sintéticas](../../tests/test_hab_rvt_literals_phase84.py) incluyen controles positivos, falsos positivos potenciales, límites de región, alineación, fallo ante hashes incorrectos y exceso de coincidencias.

## Límite de interpretación

Hasta disponer de medición independiente de la versión ROM (tabla HAB + retorno real de `get_version`), el estado sigue siendo **HAB CLOSED medido, versión HAB desconocida**. No hay ejecución de código propio, aceptación de CSF modificado, vulnerabilidad explotable ni recuperación demostradas. Esta herramienta no se conecta al dispositivo ni escribe flash o eFuses.

Referencias: [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) · [NXP, aviso autenticación adicional](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348).
