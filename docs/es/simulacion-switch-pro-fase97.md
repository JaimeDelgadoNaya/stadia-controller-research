# Fase 97 — Simulación segura de SPI 0x10 y respuestas 0x21 de Nintendo Switch Pro NS1

**Fecha:** 22/11/2026. **Tipo:** modelo offline de protocolo; no se ejecuta firmware ni se conecta ninguna consola, mando o dispositivo USB.

## Fuentes técnicas comprobadas

- [dekuNukem, subcomandos HID Nintendo](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/bluetooth_hid_subcommands_notes.md): `0x10` lee SPI; dirección little-endian de 4 bytes y tamaño de 1 byte; respuesta `0x21` con ACK `0x90/0x10` que devuelve dirección, tamaño y bytes.
- [Chromium, NintendoController](https://chromium.googlesource.com/chromium/src/+/HEAD/device/gamepad/nintendo_controller.cc): solicitudes de SPI en `0x6020` (IMU), `0x603D` (sticks), `0x6080` y `0x6086` (parámetros); datos SPI desde el índice 20 de `0x21`.
- [Linux hid-nintendo](https://codebrowser.dev/linux/linux/drivers/hid/hid-nintendo.c.html): confirma subcomando SPI y lectura de calibraciones del Pro de primera generación.
- [nxbt: sesión real documentada con Joy-Con](https://github.com/Brikwerk/nxbt/blob/master/docs/Example%20Pairing%20Session.md): aporta ejemplos de consultas `0x6080/0x18`, `0x603D/0x19`, `0x8010/0x18`; son capturas de un Joy-Con, **no** capturas propias de Switch 2.
- [Nintendo: compatibilidad de Pro NS1 con Switch 2](https://www.nintendo.com/es-es/Ayuda/Nintendo-Switch-2/Compatibilidad-de-accesorios-de-Nintendo-Switch-y-Nintendo-Switch-2-2797378.html): el accesorio original es compatible, lo que **no** prueba aceptación de firmware que lo imite.

## Implementación

`tools/simulate_switch_pro_phase97.py` ofrece un laboratorio totalmente autocontenido y **sin** importaciones USB, HID, sockets, HIDAPI, servicios ni comandos al mando. Contiene:

1. `SyntheticFactorySPI`: regiones de memoria de calibración **inventadas**, no copiadas del mando, con consultas limitadas a pares de dirección/tamaño documentados. Las regiones de calibración personal (p. ej. `0x8010`) son `FF`.
2. `VirtualNS1Pro97`: maneja `0x80 01/02/03/04`, información sintética de dispositivo (`0x02`), modo `0x30` (`0x03`), tiempo ficticio (`0x04`), envío no persistente (`0x08`), SPI `0x10`, luces `0x30`, IMU solo desactivación `0x40`, y bandera de vibración `0x48`.
3. Respuestas `0x21` de **64 bytes**, con `ACK=0x90`, eco `0x10`, dirección `LE32` y longitud en bytes `15–19`, carga útil en `20+`. Identidad MAC sintética y local.
4. Rechazo explícito de lecturas fuera de lista blanca, longitud excesiva, petición incompleta, entrada de subcomandos antes del init, IMU activo y NFC/IR `0x21`.
5. `run_offline_trace()`: traza de 13 pasos soportados y tres casos bloqueados; devuelve indicadores que no permiten afirmar compatibilidad de consola ni arranque retail.

### Comandos del laboratorio

```sh
python -m unittest tests.test_switch_pro_phase97 -v
python -m tools.simulate_switch_pro_phase97
```

**16 pruebas de fase 97 superadas en entorno local.** Además se comprueban formas, límites, valores sintéticos, respuestas de 64 bytes y seguridad. La suite de GitHub Actions debe verificarse en el commit correspondiente antes de afirmar un resultado de CI global.

## Lo que aún no está demostrado

| Componente | Estado |
|---|---|
| Traducción de controles Stadia → reportes `0x30` NS1 | Simulación previa de fase 96 |
| Respuesta `0x21` para lecturas SPI seleccionadas | Simulada con datos ficticios y pruebas locales |
| Paquete de información de dispositivo, report mode y LEDs | Simulados parcialmente |
| Sensores IMU reales, NFC/IR, vibración física | No implementados |
| Descriptor USB, endpoints, selección de configuración, tiempos | **Sin simular físicamente** |
| Captura USB completa de Pro NS1 en una Switch 2 | No obtenida / no verificada |
| Arranque del firmware en Stadia RT1061 HAB CLOSED | **No demostrado** |
| Aceptación física de emulador por Switch 2 | **No demostrada** |

**Decisión:** seguir estudiando trazas USB públicas y respuestas de calibración. No fabricar ni flashear una imagen de arranque, no ejecutar SDP ni modificar eFuses. Es incorrecto inferir que las pruebas del simulador equivalen a una consola reconociendo el mando.

**Próxima fase propuesta:** comparación byte a byte de la simulación con una traza independiente íntegra de un Pro NS1 auténtico, incluyendo descriptor USB, `0x80` init, secuencia de `0x01/0x21`, timeouts y reportes. Hasta entonces ninguna parte está validada en Switch 2.
