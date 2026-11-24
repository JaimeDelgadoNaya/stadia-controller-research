# Fase 98 — Auditoría de código BootROM real (RT1060 público), no del Stadia

**Fecha: 24/11/2026. Solo lectura de ROM pública, no hay conexión USB ni uso de firmware/flash/OTP del usuario.**

## 1. Por qué esta fase aporta evidencia nueva

Fases 93–95 comprobaron la **estructura que describe el exploit**, usando mocks o un modelo. En esta fase se comprobó el **código máquina Thumb de la imagen BootROM pública** usada por el autor, con SHA-256 que coincide con su README:

- Origen: https://github.com/Zenofex/SoC-BootROMs/blob/main/nxp/imxrt1060.bootrom.bin
- Tamaño: **131072 bytes** (ROM interna RT1060, no flash SPI del Stadia)
- SHA-256: `a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e`.
- Ejecución reproducible: [GitHub Actions #45353456221](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45353456221): **SUCCESS**, cinco tests de verificación SHA/tamaño, generación de desensamblados Thumb y artefacto textual.
- Después se incorporaron **9 firmas de opcode y 7 tests de geometría de saltos**, comprobados en un segundo workflow de fase 98. [Script](../../research/phase98/verify_claims.py).

**NOTA:** los nombres `enable_mpu`, `sdp_hid_callback` y `hab_get_config` son nombres asignados por el autor del exploit, no etiquetas oficiales integradas en ROM. El desensamblado empieza en esas direcciones y solo inspecciona ventanas acotadas, no todo el CFG.

## 2. Evidencia estática sobre MPU

En la ROM pública, la función que el autor denomina `enable_mpu` se localiza en `0x0020CAB8`.

| Dirección absoluta | Instrucción Thumb | Efecto interpretado |
|---|---|---|
| `0x0020CAD6` y `0x0020CADA` | `movw r6,#0xED94` / `movt r6,#0xE000` | Forma `r6=0xE000ED94` (registro CTRL de MPU) |
| `0x0020CAE8` | `str r1,[r6]` | `r1=0` según instrucciones precedentes: pone CTRL a cero |
| `0x0020CAF6` | `movs r7,#7` | Prepara valor no nulo |
| `0x0020CB5A` | `cmp r1,r5` | Final de ciclo de regiones |
| `0x0020CB5C` | `blo ...` | Si quedan regiones, vuelve al bucle |
| `0x0020CB5E` | `b 0x0020CB6A` | Salta por encima de la escritura de habilitación |
| `0x0020CB60` | `str r7,[r6]` | Solo accesible en una ruta anterior de salida prematura |
| `0x0020CB6A` | ... | Continuación |

Los desplazamientos en la salida relativa del desensblador son `+0xA4, +0xA6, +0xA8, +0xB2`, y las direcciones absolutas se calculan sumando la dirección de la rutina. La escritura del valor 7 en CTRL se produce en la rama ubicada justo después de un salto del camino normal.

**Conclusión acotada:** las instrucciones *corroboran* la explicación del autor: la ruta de terminación normal del bucle evita el `STR` que activaría la MPU. No se ha demostrado que todas las condiciones de ejecución reales lleven a la ruta normal ni qué otras funciones reconfiguran MPU; no equivale a un bypass de seguridad en nuestra unidad.

## 3. Evidencia estática sobre el desbordamiento HID

La función etiquetada `sdp_hid_callback` empieza en `0x0020EA7E`. El desensamblado contiene:

- `0x0020EACA`: `cmp.w r0, #0x800` (compara longitud con 2048).
- `0x0020EACE`: `bhi` hacia la salida de error para longitudes superiores.
- `0x0020EAD0`: `movw r1,#0x723f`, luego `movt r1,#0x2020` = **`0x2020723F`**.
- `0x0020EADA`: `str r1,[r2]` (pasa al USB el puntero de recepción).
- En el mismo fragmento se construye una referencia a **`0x20207A3C`**; el autor identifica `sdp_dev` ahí.

**Geometría documentada:**
- comienzo de búfer, según análisis del autor: `0x2020723C`;
- puntero de escritura HID de ROM: `0x2020723F`, **3 bytes más adelante**;
- tamaño admitido: `0x800` (2048);
- comienzo de siguiente global según el autor: `0x20207A3C`.

`0x2020723F + 0x800 - 0x20207A3C = 3`. El solapamiento de tres bytes es consistente con código real de esa ROM.

**Límite:** no se ha reproducido una transferencia USB de 2048 bytes en un chip real ni comprobado que el controlador Stadia tenga idéntico fragmento de BootROM.

## 4. Relación con firmware propio y Zephyr

El exploit contiene dos caminos:
- **Temporal (ROMC):** intenta restaurar el puntero USB y colocar un parche que simula estado HAB abierto durante ese arranque. Este código está en `SHELLCODE_ROMC`; su salida por `hid.write()` **no certifica** ejecución de código ARM en destino.
- **Permanente (FIELD_RETURN):** modifica eFuse/OCOTP. **PROHIBIDO en nuestra vía de investigación**, por irreversibilidad.

La fase 97 ya compiló un binario Thumb de 20 bytes que deja un marcador RAM; esa prueba **no está integrada** con el exploit ni se ha ejecutado en el dispositivo. Conocer offsets y 9 opcodes de la referencia RT1060 no demuestra que la ROM interna de **RT1061 Stadia** tenga el mismo código o que su mapa RAM esté libre.

Se revisó Zephyr upstream:
- [`soc/nxp/imxrt/soc.yml`](https://github.com/zephyrproject-rtos/zephyr/blob/main/soc/nxp/imxrt/soc.yml) lista `mimxrt1062` y `mimxrt1064`, **no `mimxrt1061`**.
- [`boards/nxp/mimxrt1060_evk/board.yml`](https://github.com/zephyrproject-rtos/zephyr/blob/main/boards/nxp/mimxrt1060_evk/board.yml) apunta a `mimxrt1062` y a la placa EVK.
- Su [DTS de hardware](https://github.com/zephyrproject-rtos/zephyr/blob/main/boards/nxp/mimxrt1060_evk/mimxrt1060_evk.dtsi) usa SDRAM de la placa EVK, pinmux, LED y UART propios que **no se pueden copiar a ciegas al Stadia**.

Por tanto, disponer de soporte SoC M7 de NXP en Zephyr facilita una futura adaptación, pero **no tenemos un port de placa Stadia**. `tchebb` afirma disponer de uno, todavía sin release verificable al 24/11/2026: https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/

## 5. Criterios pendientes (NO-GO)

- Identificación verificable de **BootROM interna exacta**, revisión de máscara y HAB del Stadia del usuario, distinta de la flash NOR OEM ya extraída.
- Un resultado de ejecución física confirmado mediante observación independiente (no mensajes del script).
- Diagnóstico recuperable con una unidad de pruebas y sin modificar eFuses ni flash del mando único.
- Separar ejecución temporal de firmware persistente, reinicio, dependencias de alimentación/radio y control USB.

**Estado tras fase 98:** la vulnerabilidad es técnicamente consistente con instrucciones reales de **la ROM RT1060 pública**; la ejecución en nuestra unidad Stadia permanece **NO PROBADA**. No ejecutar comandos ni exploit físico.
