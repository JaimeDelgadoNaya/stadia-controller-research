# Fase 94 — Comparación de BootROM interna RT1060/RT1061 (sin hardware)

**24/11/2026. Estado: referencia pública identificada; ROM interna del Stadia no disponible.**

## Hallazgo central

El archivo `nxp-sdp-overrun` entregado por el propietario contiene un `main.py` dirigido a i.MX RT1060 con direcciones de **ROM interna** y variables de **OCRAM** fijadas. El README dice expresamente: *"Although I have not checked, the vulnerability likely exists on other members of the i.MX RT series. Due to hardcoded offsets, the exploit will not run unmodified on other vulnerable chips."* Esa advertencia no puede tratarse como validación de RT1061.

La imagen de referencia vinculada por el autor es **Zenofex/SoC-BootROMs**, `nxp/imxrt1060.bootrom.bin`, **131072 bytes**, hash SHA-256 declarado:
`a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e`.

- Repositorio: https://github.com/Zenofex/SoC-BootROMs/tree/main/nxp
- Fuente de los offsets: ZIP `nxp-sdp-overrun` suministrado, `README.md` y `main.py`.
- Se confirmó la existencia y el tamaño del binario de referencia con GitHub. Este entorno local no pudo descargarlo (el conector GitHub rechaza binarios y no hay DNS hacia `raw.githubusercontent.com`). **Sin embargo, GitHub Actions SÍ lo descargó, verificó su hash SHA-256 y superó las ocho pruebas sintéticas**: [ejecución comprobada #45348669198](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45348669198). El reporte termina correctamente en `CANDIDATE_MISSING`: no hay ROM interna Stadia disponible.
- Ninguna ROM interna de la unidad Stadia ha sido aportada; el *dump* del bootloader A hecho en octubre de 2026 es **flash NOR externa**, no ROM NXP. Sus 131072 bytes de tamaño no la convierten en BootROM aunque coincida el tamaño.

## Datos reales de nuestro mando — medidos antes, NO hoy

`docs/es/mediciones.md` y `evidence/rom-status.json` documentan:
- `USB_ANALOG->DIGPROG = 0x006C0000`: identificador de **familia RT106x**, no submodelo ni revisión física de máscara;
- modo `ROM SDP = 1FC9:0135`;
- respuesta a `ERROR_STATUS (0x0505)`: `0x12343412` = **HAB CLOSED** y `0xF0F0F0F0` = éxito del comando. Éxito no implica HAB OPEN;
- **no** se leyó BootROM interna ni se midió la versión HAB ROM.

NXP TechSupport confirma que RT1061, RT1062 y RT1064 pueden devolver el mismo identificador `0x006C0000` y que **la ROM RT1064 difiere** del RT1060 pese a pertenecer a la familia. Por tanto el DIGPROG no constituye una huella de BootROM: https://community.nxp.com/t5/i-MX-Processors/Device-Identification-Register/td-p/1528156

NXP reconoce revisiones de silicio **A/B** y diferentes *mask sets* (`0N00X`/`1N00X`) en RT1061/RT1062. No existe una lectura verificada del *mask set* exacto de esta unidad. Tampoco debe derivarse de una etiqueta «106XA0» del programa:
https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs/RT1061-1062-Not-Recommended-for-New-Designs/m-p/1241319

## Huellas internas comparadas de forma reproducible

El verificador solo puede comparar **imágenes binarias raw de ROM interna**, no flash SPI ni un archivo de firmware firmado. Las siete ventanas de 64 bytes se centran en referencias del autor. **El comparador registra huellas SHA-256 de las siete ventanas de la ROM pública incluso sin candidata, sin marcar una comparación ficticia como positiva**:

| Símbolo nombrado por el autor | Dirección ROM | Uso como huella |
|---|---|---|
| `enable_mpu` | `0x0020CAB8` | Lógica MPU relevante |
| `USB_DeviceClassInit` | `0x0020D758` | Inicialización HID |
| `USB_DeviceEhciIsrFunction` | `0x0020E34C` | Ruta de interrupciones USB |
| `sdp_hid_callback` | `0x0020EA7E` | Ruta declarada del desbordamiento |
| `sdp_usb_pump` | `0x0020ED38` | Lazo de servicio USB |
| `sdp_usb_run` | `0x0020EF7C` | Puesta en marcha SDP |
| `HAB_GET_CONFIG_FN` | `0x002147F8` | Entrada ROM asumida para el parche |

Estos **son offsets de la ROM de referencia**: no se ha demostrado que sean punteros válidos en la ROM concreta Stadia. El script **no** traslada direcciones ni recompila el exploit.

## Artefactos

- [Comparador read-only](../../tools/compare_bootrom_phase94.py).
- [Ocho pruebas sintéticas](../../tests/test_compare_bootrom_phase94.py) ejecutadas localmente el 24/11/2026: **8/8 PASS**.
- [CI de verificación pública](../../.github/workflows/bootrom-compat-phase94.yml) descarga únicamente el binario público RT1060, exige el hash publicado, ejecuta tests y genera estado `CANDIDATE_MISSING`; no utiliza hardware ni descarga fuentes/firmware OEM privados.
- [Salida de evidencia sin ROM](../../evidence/bootrom-compat-phase94.json).

Comprobación manual *cuando ya existen ambos archivos ROM internos obtenidos legítimamente y con procedencia contrastada*:

```sh
python -m unittest discover -s tests -p 'test_compare_bootrom_phase94.py' -v
python tools/compare_bootrom_phase94.py --reference imxrt1060.bootrom.bin --candidate stadia-internal-bootrom.bin --out comparison.json
```

La herramienta diferencia `REFERENCE_MISSING`, `UNVERIFIED_REFERENCE_HASH`, `CANDIDATE_MISSING`, `REFERENCE_IDENTICAL_BYTES_PROVENANCE_UNVERIFIED`, `ONLY_SELECTED_REFERENCE_WINDOWS_MATCH` y `REFERENCE_ANCHOR_MISMATCH`.

**Criterio estricto:** Coincidir en siete ventanas no equivale a tener la misma ROM, ni prueba que el controlador alcance el callback vulnerable. Incluso un hash completo igual exige procedencia verificable de la supuesta lectura real.

## Corroboración comunitaria y límites

El 14/11/2026, `u/tchebb` comentó públicamente que había desarrollado `nxp-sdp-overrun` durante su investigación de Stadia y que había conseguido ejecutar firmware propio sobre Zephyr, **sin release aún del firmware**:
https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/

En el mismo hilo, otro participante afirmó estar probando modo Xbox Series X por BLE/cable. **Son declaraciones comunitarias, no mediciones independientes** de nuestro mando, ni un repositorio fuente o firmware público terminado.

**Interpretación:** esta pista refuerza la plausibilidad de lograr firmware propio en algún mando Stadia; no permite inferir que el script RT1060 sin modificar sirva en nuestro RT1061, que arranque después de un apagado, ni que sea seguro grabar flash.

## Estado de decisión

- **VERIFICADO:** fuente del ZIP, esquema de direcciones RT1060, datos previos de HAB CLOSED/USB SDP, 8 pruebas unitarias del comparador.
- **PENDIENTE:** ROM interna autenticada del Stadia; versión/máscara del BootROM; equivalencia de funciones/callbacks en RT1061.
- **NO-GO:** usar `--permanent`, cualquier operación FIELD_RETURN/OTP, escribir firmware o probar directamente el exploit en el mando único.
- **Siguiente hito con mejor coste/beneficio:** revisión del trabajo público de tchebb cuando publique un port RT1061/Zephyr o datos de huellas; no inventar una ROM interna a partir del backup de flash de Google.

Este documento amplía fases 81, 83, 92 y 93 sin reemplazar sus evidencias.
