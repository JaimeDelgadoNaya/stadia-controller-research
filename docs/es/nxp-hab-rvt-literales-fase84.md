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

Para cada coincidencia, una segunda pasada identifica **codificaciones Thumb potenciales de `LDR` literal de 16 y 32 bits** en una ventana anterior acotada. Esas secuencias pueden estar en datos y **no se verifican límites reales de instrucciones, flujo de control ni ejecución**. El barrido no detecta direcciones sintetizadas por `MOVW/MOVT`, sumas, tablas de punteros, saltos indirectos ni valores no alineados a 2 bytes. **Cero coincidencias no prueba ausencia de llamadas a `get_version`.** Una coincidencia tampoco prueba que la llamada exista o que pueda dispararse desde USB. Se necesitan anclajes de instrucciones originales y un flujo de control verificable.

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

## Resultados originales verificados (NXP84)

[**Evidencia exacta**](../../evidence/nxp-hab-rvt-failsafe-phase84.json) · [CI sobre dos binarios OEM con SHA-256 confirmado](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40567286976).

| Imagen firmada | Literales `RVT_BASE 0x00200300` | Literales directos `get_version 0x00200330` |
|---|---:|---:|
| **Bruce** | **2**, offsets `0x810` y `0xCD224` | **0** |
| Cargador RAM firmado | **0** | **0** |

La codificación Thumb compatible con la primera constante se ha contrastado **sobre las instrucciones OEM originales firmadas** (bytes exactos `3a48816a0847`, offset `0x726`):

```asm
0x60040726  LDR R0, [PC, #0xE8]  ; literal de 0x810 -> 0x00200300
0x60040728  LDR R1, [R0, #0x28]  ; RVT slot 0x00200328
0x6004072A  BX R1                 ; salto indirecto condicionado a entrar al stub
```

El **[código de referencia de NXP](https://github.com/nxp-mcuxpresso/sbl/blob/master/component/secure/semifunc/hab_rvt.c)** identifica el miembro `+0x28` como **`failsafe`**, seguido de `authenticate_image_no_dcd` en `+0x2C` y **`get_version` en `+0x30`**. Por tanto, **este bloque no consulta la versión HAB**; es una secuencia estática compatible con un salto al `failsafe` de ROM. Se han verificado bytes, direcciones y significado del slot, **no la ejecución real o alcanzabilidad desde USB**.

La segunda constante de Bruce (`0xCD224`) no tiene una instrucción de carga literal compatible dentro de la ventana examinada, y no se le atribuye función ejecutada.

La CI ha pasado las **45 pruebas sintéticas acumuladas de fases NXP 81–84** y los chequeos de las dos imágenes originales. El bootloader A extraído privadamente no ha sido analizado por este nuevo censo; conserva la cadena de autenticación documentada en fase 9.

## Límite de interpretación

Hasta disponer de medición independiente de la versión ROM (tabla HAB + retorno real de `get_version`), el estado sigue siendo **HAB CLOSED medido, versión HAB desconocida**. No hay ejecución de código propio, aceptación de CSF modificado, vulnerabilidad explotable ni recuperación demostradas. Esta herramienta no se conecta al dispositivo ni escribe flash o eFuses.

Referencias: [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) · [NXP, aviso autenticación adicional](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348).
