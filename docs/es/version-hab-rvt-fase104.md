# Fase 104 — HAB `get_version` en BootROM pública RT1060 (4.3.7), no Stadia

**Fecha: 24/11/2026 · Verificación: GitHub Actions · Sin hardware.**

## Resultado

Por primera vez se ha confirmado la **versión de biblioteca HAB 4.3.7 mediante el código Thumb real de la ROM pública RT1060**, no solo mediante comentarios del exploit, las cabeceras IVT/CSF o el estado HAB CLOSED.

La imagen examinada es [`Zenofex/SoC-BootROMs/nxp/imxrt1060.bootrom.bin`](https://github.com/Zenofex/SoC-BootROMs/blob/main/nxp/imxrt1060.bootrom.bin), tamaño **131072 bytes** y SHA-256 **`a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e`**, ya fijado en fases 94, 98 y 100.

**No existe aún imagen ROM interna de procedencia verificable del Stadia del usuario.** Estos hallazgos se refieren exclusivamente a la ROM pública RT1060; **no certifican que el Stadia tenga HAB 4.3.7 ni que el exploit sea aplicable**.

## Tabla HAB RVT: bytes extraídos

La **ROM Vector Table (RVT)** se encuentra en `0x00200300`, que el manual [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) describe. Mediante el validador de la [fase 83](../../tools/audit_hab_rom_version_phase83.py), aplicado a bytes *reales* del fichero RT1060 y no a snapshots sintéticos:

| Campo | Valor público RT1060 | Interpretación |
|---|---|---|
| Tag | `0xDD` | Encabezado HAB RVT |
| Tamaño declarado | **56 bytes** | Longitud de la tabla |
| Byte de versión de cabecera | **`0x43`** | Formato HAB 4.3, **no patch 4.3.7** |
| Dirección del slot `get_version` | `0x00200330` | Posición **del puntero**, no función |
| Valor Thumb del slot `get_version` | **`0x00202171`** | Dirección efectiva código `0x00202170` |
| Dirección del slot `authenticate_image_no_dcd` | `0x0020032C` | Posición del puntero |
| Valor Thumb de ese slot | **`0x002034D1`** | Otro punto de código ROM |

### Constante de retorno de `get_version` en código real

A partir de `0x00202170`, el desensamblado de la ROM pública muestra:

```asm
0x00202170  push  {r0, r1, r2, lr}
0x00202172  ldr   r3, [pc, #0x18]
0x00202174  ldr   r0, [pc, #0x18]
...
0x00202180  beq   0x00202186
...
0x00202186  add   sp, #0xc
0x00202188  ldr   pc, [sp], #4
```

El opcode Thumb16 de `LDR r0` en `0x00202174` es **`0x4806`**. El valor de PC base alineado + desplazamiento de ese opcode apunta a la **palabra literal en `0x00202190`**; los 4 bytes, leídos de la referencia ROM, codifican **`0x00040307`**, es decir, **HAB 4.3.7** en la ruta normal de retorno.

La función también contiene una comprobación de integridad tipo *stack protector* (carga, compara y eventualmente llama a un manejador de fallo). **No se ha ejecutado ni emulado íntegramente `get_version`; se extrajo el literal con análisis estático de código máquina y se verificó la ruta normal aparente.**

La afirmación del autor `tchebb` de que su `nxp-sdp-overrun` trabaja sobre ROM i.MX RT1060 HAB 4.3.7 es **congruente con estos bytes**: https://codeberg.org/tchebb/nxp-sdp-overrun . No demuestra validez en todas las máscaras/revisiones RT1061.

## Fuentes nuevas contrastadas: registro de arranque ≠ log HAB

En una [consulta de NXP en agosto/septiembre de 2026](https://community.nxp.com/t5/Other-NXP-Products/i-MXRT106x-HAB-closed-boot-fail-HAB-log-stops-at-AUTHENTICATION/m-p/2409914), el soporte señala:
- El contenido de `0x2020523c` es el **ROM boot log**, no el log detallado de eventos HAB.
- `blhost` se comunica con el **flashloader**, no con ROM SDP. Que el cargador tenga `GetProperty` no supone que exponga la revisión de ROM.
- Con HAB CLOSED y fallo de autenticación, el salto al programa puede estar bloqueado antes de que este pueda llamar a `report_event`.

Son observaciones generales de NXP en otra plataforma RT106x, **no mediciones del mando Stadia**. El mismo hilo discute restricciones particulares a imágenes **Non-XIP** y direcciones OCRAM bajo HAB; esos condicionantes todavía no están ensayados con el firmware RAM hipotético de fase 100.

## Estado del Stadia observado (no modificado)

Las [mediciones archivadas](mediciones.md) siguen siendo:

| Medición del usuario | Valor | ¿Demuestra versión ROM? |
|---|---|---|
| USB SDP | `1FC9:0135` | **No** |
| `ERROR_STATUS 0x0505` | `0x12343412` HAB CLOSED | **No** |
| Estado de comando HAB | `0xF0F0F0F0` (éxito) | **No** |
| `DIGPROG` | `0x006C0000` familia RT106x | **No** |
| IVT/CSF en imágenes OEM | `0x41`/`0x42` | **No** |

La tabla del cargador RAM firmado tampoco enumera `0x00200000–0x0021FFFF` entre sus regiones accesibles habituales [fase 99](romc-y-lectura-bootrom-fase99.md). No existe un resultado `get_version` medido en la unidad ni un dump interno válido.

## Implementación y pruebas

- [Auditor SHA-pinned público](../../research/phase104/audit_hab_rvt_reference.py).
- [11 pruebas sintéticas y de rechazo](../../tests/test_hab_rvt_reference_phase104.py).
- [GitHub Actions](../../.github/workflows/phase104-public-hab-rvt.yml): descarga la ROM pública validada por SHA, decodifica el RVT y verifica el opcode `0x4806` y el literal `0x00040307`, con salida JSON.
- [Evidencia saneada](../../evidence/hab-rvt-getversion-phase104.json).

## Decisión técnica

**Hito logrado:** identificar objetivamente HAB **4.3.7 en la referencia** y establecer un procedimiento reproducible para detectar la versión si se obtiene una ROM de origen comprobado.

**Hito pendiente y fundamental:** demostrar que **la máscara BootROM real del Stadia** tiene el mismo RVT, punteros y función; sin una fuente verificable, no se puede usar este resultado para autorizar pruebas físicas ni afirmar ejecución temporal o permanente. Mantener prohibidos `FIELD_RETURN`, OTP y el flashing de un único dispositivo.
