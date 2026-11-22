# Stadia ficticio → firmware Xbox 360: instalación virtual completada

**22 de noviembre de 2026 · Fases 101–102 · Laboratorio offline sin hardware.**

> **Resultado correcto:** dos instalaciones lógicas de un paquete *ficticio* XUSB en un controlador virtual A/B (OPEN sin firma, CLOSED con firma de laboratorio). En ambos casos, tras la conmutación, `boot()` verifica el manifiesto y `health()` ejecuta mediante Python el conversor real de fase 99. Se genera un reporte Xbox 360 de 20 bytes cuando se pulsa A. **No hemos instalado ni ejecutado binarios ARM para el i.MX RT1061** y **no hemos autenticado una imagen con HAB real**.

## 1. Esquema del laboratorio

```text
Fuente C11 del conversor (fases 99-100)
                  │
     huella SHA-256 + marca de laboratorio
                  │
          Bundle (manifest + payload)
                  │
       Firma Ed25519 efímera OPCIONAL
                  │
          ┌───────▼────────┐
          │ Stadia FICTICIO│
          │ banco A / B    │
          └───────┬────────┘
                  │
   escribir solo banco inactivo → validar contenido → autenticar
                  │
          cambiar puntero virtual de arranque
                  │
           reboot + comprobación de codec
                  │
             confirmar o rollback
                  │
      host XUSB FICTICIO: paquete IN de 20 B / rumble bytes
```

**Este laboratorio no representa** la geometría NOR, proceso ROM real, eFuse/OTP, imagen IVT/Boot Data/CSF, autenticación RSA de HAB, relojes, drivers USB, timings físicos ni ejecución de instrucciones Cortex-M7. Ed25519 se usa como **instrumento real de criptografía de ensayo**, pero NO como sustituto compatible con la firma de NXP. Todas las claves se generan de nuevo en memoria en cada ejecución; no son claves OEM y no se incluyen en archivos exportados.

## 2. Resultados que reproducimos

| Ensayo | Resultado virtual | ¿Demuestra viabilidad en Stadia real? |
|---|---|---|
| Desarrollo OPEN, XUSB sin firma | **Instalado y arrancado en banco B** | No |
| Laboratorio CLOSED, firma válida de su clave de prueba | **Instalado y arrancado en banco B** | No; esa clave no está en un Stadia comercial |
| CLOSED, paquete sin firma | **Rechazado** (se mantiene banco A) | Solo valida la lógica del modelo |
| CLOSED, clave distinta / firma manipulada | **Rechazado** | Solo valida el modelo |
| Manifiesto/payload manipulados | **Rechazados** | Solo valida integridad en software |
| Corte de energía al escribir el banco B | **Retorno a A** | No prueba la atomicidad real de hardware |
| Corte antes de actualizar el puntero | **Retorno a A** | No |
| Corte después de actualizar el puntero | **Rollback a A** | No |
| Corte antes de confirmar actualización | **Rollback a A** | No |
| Nueva aplicación con fallo de salud | **Rollback a A** | No |
| Aplicación arrancada + botón A | **Genera XUSB de 20 B** | Codec probado solo en PC |
| Host Xbox 360 virtual, estructura de interfaces USB | **Chequeo estructural correcto** | No implica enumeración real en Windows |
| Host virtual, comando rumble | **Traduce a 5 B Stadia** | No mueve motores |

El cargador virtual `install()` realiza una operación de almacenamiento en **banco inactivo** y exige validación estructural y, en CLOSED, una firma aceptada **antes** de alterar el puntero. Si falla la comprobación funcional, recupera el último banco confirmado. La política anti-rollback por versión se representa como un campo en RAM (no como eFuse).

## 3. Pruebas ejecutadas

- **95 pruebas unitarias** satisfactorias (30 nuevas de arranque/instalación, 8 nuevas del host y 57 heredadas del codec, USB y auditoría de arranque).
- Una prueba de propiedades reproduce **500** combinaciones deterministas adicionales de modo OPEN/CLOSED, clave firmante, versión, y distintos momentos de fallo eléctrico.
- Las pruebas heredadas incluyen **1.500 vectores sintéticos diferenciales** Python ↔ compilación C11 portable, aunque son comprobaciones del codec en CPU anfitriona, no del procesador Stadia.
- Todas las pruebas se ejecutan offline sin módulos USB ni acceso a memoria de ningún dispositivo.

Reproducir desde la raíz del paquete:

```bash
python -m unittest discover -s tests -v
python -m tools.virtual_stadia_firmware_phase101
```

Dependencia: `cryptography` (para claves efímeras Ed25519). La comprobación diferencial C11 requiere un compilador C (`cc`) y puede omitirse si falta. El ZIP **no contiene material de emparejamiento, firmware extraído del mando ni imágenes flasheables**.

## 4. Qué nos dicen los archivos anteriores sobre el hardware real

- `message.txt` describe una transición a SDP mediante petición USB 0xC0 de tipo Class en la aplicación **169429**, según su autor. Esto no prueba que ocurra en todas las revisiones ni que SDP omita HAB.
- `bootloader-usb-acm(1).bin`: 94.248 B y 72 bytes distintos respecto a la parte compartida del original; puntero CSF eliminado y fichero truncado antes del CSF original. Esto **no pasa** una validación criptográfica de arranque cerrado.
- `thebb_ivt_flashloader.bin`: IVT en +0x400, puntero CSF nulo; declara 98.304 B y contiene 98.148 B (156 bytes menos). Este cargador tampoco representa una vía demostrada de arranque autenticado.
- `bluetooth-image-public.md`: botones, ejes y estructura interna del firmware Bruce documentados por terceros; base del codec fase 99.
- `fwlog-kit.zip`: las herramientas del autor pueden tocar memoria, flash, SDP y reset; **no se ejecutaron**. La experiencia del autor en placa de desarrollo no demuestra HAB CLOSED de retail.
- `bluetooth(1).bin`: almacén `#BONDING` privado. No se ha leído ni incluido.

## 5. La diferencia entre el éxito virtual y una instalación real

NXP distingue el protocolo Serial Downloader del proceso de autenticación HAB. La documentación indica que una imagen no autenticada en **CLOSED** no se ejecuta, aunque exista transporte de carga. En una unidad real hay que demostrar **cuál es su estado de seguridad**, cuál es su **cadena de confianza efectiva**, y disponer de una **ruta de arranque y recuperación probada**; el hecho de disponer de un paquete ficticio firmado con claves efímeras no sirve para eso.

Fuentes oficiales de referencia:
- [NXP — i.MX RT1060 Manufacturing Guide, Introduction](https://docs.mcuxpresso.nxp.com/mcuxsdk/latest/html/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/introduction.html)
- [NXP — i.MX RT bootable image: IVT, Boot Data, CSF](https://mcuxpresso.nxp.com/mcuxsdk/25.06.00/html/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/imx_rt_bootable_image.html)
- [NXP — Program bootable image](https://docs.mcuxpresso.nxp.com/mcuxsdk/latest/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/program_bootable_image.html)

### Siguiente paso recomendado

1. Usar las pruebas actuales para validar un **prototipo XUSB en una placa RT1060/RT1062 de desarrollo recuperable**, sin alterar la unidad Stadia. El ordenador anfitrión debería enumerar el dispositivo con un controlador USB propio y recibir los reportes; la compatibilidad real con XInput aún debe observarse y puede depender de detalles adicionales o drivers.
2. Obtener información **no destructiva** sobre revisión/firmware y estado de seguridad del Stadia. No asumir CLOSED solo por la procedencia comercial y no modificar eFuses o `FIELD_RETURN`.
3. Contrastar si hay una cadena de actualización oficialmente autenticable o un procedimiento de investigación reproducible y recuperable. **No flashear** sin demostrarlo.

**Alcance de la conclusión:** ya logramos una **instalación A/B virtual funcional**, no una instalación en hardware Stadia ni en un emulador de CPU Cortex-M7.
