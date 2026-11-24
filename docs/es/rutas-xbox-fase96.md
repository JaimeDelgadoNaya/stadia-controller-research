# Fase 96 — Estado del firmware Stadia y alternativas Xbox sin desbloqueo

**Fecha de corte: 24/11/2026. Investigación documental y simulación offline. No se ha conectado hardware.**

## Hallazgo 1: trabajo público del autor del exploit

En el hilo [Has anyone bypassed the bootloader signage?](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) del 14–15/11/2026, `tchebb`, autor de `nxp-sdp-overrun`, declara:
- que encontró la vulnerabilidad durante su investigación del mando Stadia;
- que ha portado **Zephyr al Stadia Controller** y dispone de firmware personalizado que funciona razonablemente bien, **no listo para publicar**;
- que desea preparar un flasheador web y firmware para mandos Switch, todavía no publicados.

Son **declaraciones de primera mano del autor**, no una imagen de firmware descargable, ni evidencia verificada de ejecución en nuestra unidad. No se localizó una publicación verificable del port Stadia/Zephyr con el código de fuentes y estado de release. El ZIP `nxp-sdp-overrun` ya auditado en fases 93–95 no contiene dicho firmware.

Por tanto, **no afirmar instalación, persistencia ni ejecución propia por el usuario**.

## Hallazgo 2: opción BLE + USB Xbox 360 ya implementada en código fuente público

El proyecto `danzig666/stadia-dongle-esp` publica **código ESP-IDF para ESP32-S3**:
https://github.com/danzig666/stadia-dongle-esp

Verificado contra commit `d8392de8f838e12cf16c985b9beb8080c7acd970`, fichero original `main/bridge.c` con Git blob SHA `2474636aceb6c6a3ba935f85514148b939ced63c`.

- `main/ble_central.c`: BLE central para recibir informes del mando original.
- `main/bridge.c`: transforma notificaciones Stadia BLE **de 10 bytes** en informes de entrada Xbox 360 USB **de 20 bytes**; define cruceta, A/B/X/Y, bumpers, sticks con inversión Y, triggers y botón guía.
- `main/usb_xbox.c`, `main/xbox_dev.c`: descriptores/interfaz USB Xbox 360 mediante TinyUSB.
- El repositorio documenta rumble hacia BLE y conexión de hasta 2 mandos, además de web installer.

**Evidencia observada:** código y README públicos. **No:** compilación ESP-IDF ni prueba sobre un ESP32-S3 físico en esta fase. El firmware se instalaría en **el dongle externo**, no en el Stadia.

El diseño es para **Windows/PC y otros hosts USB compatibles**, no prueba autenticación con una **Xbox Series X/S física**.

## Hallazgo 3: Stadiacast y Stadia-X

- [Stadiacast](https://github.com/jkfran/stadiacast), versión reciente publicada en PyPI en noviembre 2026, permite que **Windows presente un mando virtual Xbox 360 con ViGEmBus**, incluido rumble. Requiere **firmware Wi-Fi Gotham** (`ota.282115`) en el mando, red/DNS local y software receptor. No es cambio directo de firmware. Si el usuario tiene Bruce Bluetooth, volver a Gotham supone una operación de flash independiente que no proponemos en el único mando.
- [Stadia-X](https://github.com/offvault/Stadia-X/releases) implementa un puente con Bluetooth mediante WSL2 + ViGEmBus, sin tocar la flash del controlador. Instalación más compleja y componentes de sistema/USB; fiabilidad no ensayada aquí.

Comparación operativa en esta investigación:

| Camino | Firmware Stadia cambiado | Hardware adicional | Windows como Xbox 360 | Xbox física |
|---|---:|---|---|---|
| Firmware Zephyr directo (`tchebb`) | Sería necesario | No aclarado | No existe release público verificado | No demostrado |
| Dongle ESP32-S3 BLE | **No** | **Sí, dongle** | Implementación fuente pública | No demostrado |
| Stadiacast Wi-Fi | **No mientras ya tenga Gotham** | No, pero requiere PC/red | Función documentada | No demostrado |
| Stadia-X Bluetooth | **No** | No (PC con Bluetooth, WSL2) | Función documentada | No demostrado |

## Simulación propia fase 96: informes Stadia → Xbox 360 (modelo independiente)

Se ha creado y ejecutado un **modelo Python original** que reproduce el *esquema documentado* de `bridge.c`, sin usar ni compilar el C externo. Se aplicaron **18 tests sintéticos / 18 PASS**:

1. Trama neutra de 20 bytes con cabecera `00 14`.
2. Las ocho posiciones de cruceta (un test con subcasos).
3. Valor fuera de rango para cruceta.
4. A/B/X/Y.
5. LB/RB.
6. Botón Stadia → Guide.
7. Menu/Options → Start/Back.
8. LS/RS click.
9. Gatillos analógicos.
10. Centros de sticks.
11. Extremos de sticks.
12. Inversión vertical.
13. Ejes horizontales.
14. Assistant/Capture sin equivalencia XInput.
15. Relleno final.
16. Rechazo de informe corto.
17. Rechazo de informe largo.
18. Combinación de botones + cruceta.

**Interpretación:** el *formato de salida* puede modelarse coherentemente. **No valida** BLE real, periférico USB, compilación del dongle, aceptación por Windows/Xbox física, rumble físico, latencia, persistencia ni bypass HAB. La simulación y sus pruebas están en el ZIP local `Stadia_Investigacion_Fase96.zip`, disponible en esta conversación.

## Ruta principal y siguiente criterio

Aun existiendo alternativas Xbox para **PC**, el objetivo de **firmware modificado directamente en Stadia** sigue bloqueado por evidencias:
1. El ZIP del exploit fija offsets de BootROM RT1060 y no aporta una huella verificada de la ROM interna de nuestra unidad RT1061.
2. El informe fase 94 tiene ROM pública RT1060 con hash verificado y siete huellas, pero no copia interna del mando.
3. `tchebb` declara un port funcional, pero no lo ha publicado; terceros mencionan parches Xbox BLE/cable en pruebas, **no una versión descargable y verificada**.

Siguiente hito: obtener fuente/artefactos publicados con compatibilidad exacta Stadia RT1061 y procedencia reproducible, o huella verificable de ROM interna, sin probar `--permanent`, `FIELD_RETURN`/OTP ni escribir el único mando.

## Enlaces de evidencia
- `tchebb`, publicación y estado Zephyr: https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/
- Código BLE→Xbox: https://github.com/danzig666/stadia-dongle-esp/blob/d8392de8f838e12cf16c985b9beb8080c7acd970/main/bridge.c
- Código TinyUSB: https://github.com/danzig666/stadia-dongle-esp/blob/main/main/xbox_dev.c
- Stadiacast: https://pypi.org/project/stadiacast/ ; https://github.com/jkfran/stadiacast
- Stadia-X: https://github.com/offvault/Stadia-X/releases

**NO-GO físico del Stadia preservado.** Este reporte no sustituye a fases 93–95 ni acredita una instalación de firmware personalizada.
