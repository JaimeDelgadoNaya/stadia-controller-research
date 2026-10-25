# Fase 31 — Cierre de la investigación de ejecución interna: autenticación y recuperación

**Resultado del segundo y último paquete offline: PARAR la vía de firmware interno y priorizar el puente externo.**

Esta es una decisión de ingeniería **bajo el criterio de parada pactado**, no una afirmación de que sea matemáticamente imposible modificar cualquier Stadia en el futuro. El requisito era demostrar simultáneamente **una entrada controlable desde el ordenador, una ejecución propia autorizable y recuperación fiable**. Los dos últimos requisitos **no** se han demostrado.

## Muestras y autenticación independiente

Se han examinado las dos imágenes privadas verificadas por SHA-256, **sin enviarlas al mando**:

| Muestra | SHA-256 | IVT / CSF | Verificación |
|---|---|---|---|
| Bootloader A extraído, 131.072 bytes | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` | IVT en offset `0x0`, CSF en `0x18000` | **Dos firmas RSA/CMS válidas**, digests coincidentes |
| `bruce_pvt_a_prod_signed(1).bin`, 1.050.984 bytes | `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3` | IVT en `0xFF000`, CSF en `0xFF030` | **Dos firmas RSA/CMS válidas**, digests coincidentes |

Los resultados se han recalculado usando el método del verificador existente `tools/verify_hab.py`, que valida los hashes de contenido y firmas CMS con certificados presentes en el propio archivo. Al cambiar **un byte de código en una copia de cada imagen**, ambas verificaciones de digest fallan como se espera. Las copias originales permanecieron intactas.

**Cobertura de los bloques firmados:**

- Bootloader A: `0x60001000`, longitud `0x1000`, representa explícitamente un alias a offset de archivo 0; y `0x60800000`, longitud `0x18000`, también desde offset 0. La doble representación no significa que toda la flash esté duplicada.
- Bruce: bloque desde `0x60040000` de longitud `0xFF030`, offset de archivo 0. Contiene código y la IVT que apunta al CSF.

**Límite criptográfico:** se verifican **matemáticamente** las firmas y los hashes de las regiones declaradas, **no se lee ni verifica aquí el hash SRK programado en los fusibles**. Que el fichero de aplicación coincida byte a byte con toda la app instalada **tampoco está demostrado**.

## HAB CLOSED y verificación antes de ejecutar

En las [mediciones físicas anteriores](mediciones.md) de esta unidad, la ROM devolvió `ERROR_STATUS = 0x12343412` (**HAB CLOSED**), reportó `0xF0F0F0F0` (**HAB Success**) y el cargador original firmado devolvió `GetProperty 0x11 = 1`. La rutina `0x2000A87C` del cargador inspeccionado lee `OCOTP_CFG5[1]`, por lo que esta respuesta corresponde a la seguridad de arranque de esa unidad y no a un nombre genérico de propiedad.

Se ha contrastado con huellas de código del bootloader la cadena documentada en [fase 9](arranque.md):

- `0x60801F00` llama al **validador `0x6080200C`**. Solo cuando tiene éxito continúa hasta el salto real a aplicación en `0x60801F46`.
- `0x60801F5C` llama a la tabla de entrada ROM HAB `0x00200304` (entry), `0x0020032C` (authenticate_image_no_dcd) y `0x00200308` (exit), y comprueba el resultado esperado.
- `0x608020A8` permite una **prevalidación estructural sin autenticación** cuando recibe una bandera cero. El camino con bandera uno llega a autenticación HAB antes de considerar válida la imagen. **Superar la prevalidación estructural no es autorizar código propio.**

La documentación NXP describe la función IVT/CSF de imágenes firmadas y la política de HAB CLOSED: no se permite ejecución de código no autenticado en la cadena habitual de arranque.

Referencias de arquitectura NXP:
- [NXP, *i.MX RT bootable image*](https://mcuxpresso.nxp.com/mcuxsdk/latest/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/imx_rt_bootable_image.html)
- [NXP, RT1060 Reference Manual](https://www.pjrc.com/teensy/IMXRT1060RM_rev2.pdf)
- [NXP, HABv4 y autenticación de imágenes](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/112842/1/AN4581.pdf)

## Ruta de actualización que sí está documentada

En el [paquete A](protocolo-actualizador-webhid.md) ya quedó identificada:

```text
Ordenador — WebHID
   → ROM NXP SDP 1FC9:0135
   → carga del flashloader original firmado en RAM
   → flashloader 15A2:0073 (borrado, programación, reinicio)
   → bootloader original + comprobación HAB
   → imagen Google firmada
```

Es una cadena de programación física prevista por el fabricante, **no una ruta acreditada para ejecutar firmware modificado**. El hecho de que el cliente pueda enviar un comando `WriteMemory` no demuestra que una imagen alterada arranque. El mensaje candidato de la app en `0x60058B68` tampoco se ha relacionado con el protocolo de actualización documentado.

## Recuperación real

| Condición | Evidencia | Evaluación |
|---|---|---|
| Acceso a ROM SDP | Se alcanzó previamente en esta unidad | **Sí, comprobado** |
| Cargador original firmado en RAM | Fue aceptado anteriormente | **Sí, comprobado** |
| Flash backup de bootloader B | Los 128 KiB se leyeron como `0xFF` | **No hay redundancia operativa** |
| Copia íntegra de todos los 16 MB y del firmware instalado | No disponible | **No comprobada** |
| Recuperación tras actualización interrumpida/imagen propia no válida | Nunca probada | **No garantizada** |
| Arranque de firmware propio en HAB CLOSED | No probado | **No demostrado** |

**Importante:** disponer de acceso ROM o de una imagen comercial firmada puede ayudar en una recuperación concreta; **no permite prometer rollback** tras cualquier fallo, ni reemplaza una prueba recuperable en un mando secundario. No se ejecutará una actualización experimental en el único mando disponible.

## Árbol de decisión definitivo

```text
¿Existe canal real host → memoria?                     SÍ (WebHID y flashloader firmado)
                │
¿Se ha demostrado ejecutar código propio autenticable? NO
                │
¿Se ha verificado recuperación fiable/rollback?         NO
                │
        PARAR MODIFICACIÓN INTERNA
                │
        PUENTE EXTERNO REVERSIBLE
```

**Resultado del criterio pactado: STOP interno, GO para prototipo externo.** El firmware original y la electrónica del mando se mantienen intactos.

## Prototipo siguiente: Stadia → puente externo → Xbox

Primera prueba **sin comprometer aún compatibilidad de consola**:

1. Mando Stadia con firmware Bluetooth oficial; receptor ESP32-S3 con BLE y USB nativo. Referencia: [danzig666/stadia-dongle-esp](https://github.com/danzig666/stadia-dongle-esp). Su documentación declara **compatibilidad con PC** como gamepad Xbox 360 y soporte de botón y ejes analógicos.
2. Comprobar en PC emparejamiento, desconexión/reconexión, sticks, triggers, vibración y latencia. **No modificar el mando original**.
3. Solo para Xbox One/Series, elegir una **interfaz o accesorio realmente compatible y autorizado**, con prueba del modelo específico. Una enumeración USB como Xbox 360/XInput para PC **no** demuestra que una Xbox física lo acepte.
4. Definir posteriormente BOM y costes del prototipo en función de consola objetivo y accesorio certificado, sin prometer autenticación emulada.

No abrir más fases de búsqueda genérica de punteros ARM salvo que aparezca **una prueba externa nueva** de firma autorizable/ejecución propia recuperable que cambie los criterios.

## Reproducibilidad (offline)

```sh
python tools/audit_final_auth_recovery.py local/bootloader-a.bin local/bruce_pvt_a_prod_signed.bin --out local/phase31-final.json
python -m unittest discover -s tests -v
```

El auditor valida SHA-256 íntegros, IVT, CSF, firmas CMS/RSA, bloques autenticados, huellas de código y la decisión STOP/GO. GitHub Actions prueba modelos e imágenes sintéticas; **no contiene las dos imágenes originales**.
