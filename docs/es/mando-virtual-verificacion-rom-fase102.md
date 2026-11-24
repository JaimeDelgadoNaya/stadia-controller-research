# Fase 102 — Mando Stadia virtual con control de procedencia de BootROM

**24 de noviembre de 2026. Investigación y pruebas offline. No se ha conectado ni alterado el mando.**

## Resultados nuevos

1. Se revisó la documentación de NXP: el aviso de cambio de producto [PCN 202007035F01U01](https://www.nxp.com/pcn/202007035F01U01) identifica revisiones de silicio **0N00X / 1N00X** en la familia RT1060, que incluye opciones RT1061. La ficha de [MIMXRT1061DVL6A](https://www.nxp.com/part/MIMXRT1061DVL6A) enlaza ese aviso. **No se conoce qué revisión monta nuestra unidad**; el registro `DIGPROG=0x006C0000` observado anteriormente identifica la familia, no demuestra equivalencia de ROM.
2. El último anuncio público comprobado de `tchebb` en el [hilo de r/Stadia](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) declara firmware Zephyr funcional pero no listo para publicación. **No se encontró en esta revisión una publicación verificable** del port de la placa Stadia. La fuente Codeberg no estaba accesible para inspección en esta búsqueda, por lo que no se afirma categóricamente que el port no exista.
3. Se corrigió un problema epistemológico de fase 101: el perfil «Stadia observado» mostraba que un informe de **2048 bytes** había sido aceptado por su BootROM sin haberlo medido en la unidad. En fase 102 el perfil **bloquea** esa transición; solo el perfil «ROM pública RT1060» la presenta como comprobada, y ni siquiera ese perfil permite el paso ROMC.
4. El nuevo mando virtual HTML ofrece **tres escenarios** con estados y garantías separados:
   - **Stadia observado:** USB `1FC9:0135`, HAB CLOSED y familia RT106x de observaciones de octubre de 2026; BootROM interna desconocida; no se afirma aceptación del callback HID, ROMC ni firmware.
   - **ROM pública RT1060:** acepta una comparación HID de 2048 bytes **basada en instrucciones reales emuladas en fase 100**; bloquea ROMC y firmware propio.
   - **Cadena hipotética:** supone compatibilidad ROMC y aceptación de imagen unsigned; el intérprete del demo ARM produce el marcador virtual `0x5A`, que se pierde al reiniciar. **No es una ejecución real**.
5. Nuevo **comparador local de ROM** en el mismo HTML: selecciona un archivo `.bin` de **exactamente 131072 bytes** y calcula su SHA-256 completo y el SHA-256 de **siete ventanas de 64 bytes**. Las referencias provienen de la ROM pública RT1060 validada en GitHub Actions [fase 94](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45348902534). Las siete ventanas cubren los símbolos asignados por el autor para `enable_mpu`, `sdp_hid_callback`, `sdp_usb_run`, `sdp_usb_pump`, `HAB_GET_CONFIG_FN`, `USB_DeviceClassInit`, `USB_DeviceEhciIsrFunction`.

**Límite esencial:** una coincidencia de SHA-256 establece igualdad de *bytes del archivo seleccionado*. NO demuestra que ese archivo sea una lectura verificada de la **BootROM interna del Stadia** (un backup de la NOR externa de 128 KiB puede tener el mismo tamaño) ni que el exploit funcione en nuestro RT1061. El comparador **nunca desbloquea** el perfil observado. Tampoco cambia ROMC, HAB, RAM, flash ni fusibles en hardware.

## Verificación ejecutada localmente

- **12/12 pruebas unitarias** del comparador Python: tamaño, SHA-256, siete ventanas, tampering, diferencia fuera de las ventanas y estado de procedencia no verificable.
- **6/6 vectores SHA-256** en Node.js: casos vacíos, `abc`, contenido ASCII, 131072 ceros, datos aleatorios y un byte `0xFF`, contrastados con `crypto.createHash`.
- **17/17 comprobaciones de navegador Chromium + Playwright**, en un contexto aislado: cambio de perfiles, bloqueo en observado, paso ROM pública y bloqueo ROMC, marcador hipotético y pérdida tras reset, rechazo de fichero corto, hash de archivo ficticio de 128 KiB y siete ventanas, exportación JSON y ausencia de excepciones.
- La CI de GitHub descargará y verificará **la ROM pública real** antes de contrastar las siete huellas del manifiesto. Las pruebas locales sintéticas no sustituyen esa validación independiente.

## Instrucciones

Abrir `StadiaVirtual102.html` con Chrome/Edge/Firefox moderno. No requiere red ni conexión USB. Seleccionar el perfil y pulsar «Ejecutar escenario completo». Para comparar un archivo que ya se tenga legítimamente, seleccionar su archivo binario en el cuadro **Comparador local de BootROM**. El navegador calcula los hashes sin subir el contenido. Si se desea, exportar el JSON del resultado. No enviar firmware al mando.

### Qué está pendiente

- Un dump autenticado o una huella verificable de la **BootROM interna** del RT1061 *de la unidad concreta*.
- Contrastar máscara de silicio, versión HAB y funciones reales ROMC/HID, sin inferirlo del DIGPROG.
- Código o binario publicado y verificable del port de Zephyr específico de Stadia.
- Prueba física recuperable e independiente de ejecución temporal del demo ARM, sin eFuse y sin escritura en la única unidad.
- Integración futura de entradas reales (GPIO/ADC/BLE/USB) y evaluación de persistencia: pasos distintos del marcador de 20 bytes.

**NO-GO:** `--permanent`, `FIELD_RETURN`, OTP/eFuse y flashear el único mando siguen excluidos.