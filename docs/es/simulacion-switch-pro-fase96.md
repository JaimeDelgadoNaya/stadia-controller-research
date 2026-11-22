# Fase 96 — Simulación del mando Stadia como Nintendo Switch Pro (NS1), sin hardware

**Fecha:** 22/11/2026. **Estado:** prueba de protocolo parcial. No se ha emulado el procesador i.MX RT1061, ejecutado firmware, conectado una Switch 2 ni eludido HAB CLOSED.

## Por qué es mejor estudiar NS1 Pro antes que NS2 Pro

Nintendo **confirma la compatibilidad del mando Pro original de Switch con Switch 2** y la opción de comunicación cableada desde *Configuración → Mandos y sensores / Controllers & Accessories → Nintendo Switch Pro Controller Wired Communication*. Esto demuestra compatibilidad con el accesorio genuino, **no** aceptación de una emulación no verificada.

- [Nintendo España: compatibilidad de accesorios](https://www.nintendo.com/es-es/Ayuda/Nintendo-Switch-2/Compatibilidad-de-accesorios-de-Nintendo-Switch-y-Nintendo-Switch-2-2797378.html).
- [Nintendo: activar comunicación USB de Pro original en Switch 2](https://en-americas-support.nintendo.com/app/answers/detail/a_id/68263/).
- [dekuNukem: comandos USB HID](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/USB-HID-Notes.md).
- [espp: emulador de protocolo Pro NS1 sin transporte](https://esp-cpp.github.io/espp/hid/switch_pro.html).

El mando Pro NS1 usa normalmente `057E:2009`, intercambio de iniciación `0x80→0x81`, salida `0x01`, subrespuestas `0x21` y reportes de entrada `0x30`. No se debe confundir con el Pro NS2 nativo `057E:2069`, cuya vía de protocolo es diferente.

## Resultado offline

Hay un conversor independiente `tools/simulate_switch_pro_phase96.py` y tests `tests/test_switch_pro_phase96.py`, además de un paquete descargable con pruebas más exhaustivas.

El archivo fuente Bruce original está documentado como un reporte HID **11 bytes**: `03`, hat, dos bytes de botones, cuatro ejes de 8 bits, dos gatillos y un byte Consumer. Los 15 botones están en bits 0–14. No se ha leído ningún paquete nuevo del mando físico en esta fase.

| Capa | Modelo y resultado | Límite |
|---|---|---|
| Botones y hat | Mapeo completo de 15 bits; hat 0–7 y neutro 8 | Assistant y Consumer audio no tienen equivalente |
| A/B/X/Y | Por *letras* o *posición física* | Por posición: A↔B y X↔Y |
| Sticks | 8 bits a 12 bits, empaquetado Nintendo de 3 bytes por stick | No recupera precisión analógica real |
| Gatillos | Umbral 128 para botones digitales ZL/ZR | Se pierde el valor analógico |
| Reporte `0x30` | 64 bytes sintéticos; las muestras IMU son ceros | No demuestra sensores ni compatibilidad de consola |
| Init `80 01/02/03/04` | Respuestas `81 01/02/03` y transición a streaming modeladas | No enumeración USB real |
| Subcomando `01/03` | Cambio de modo a reporte `0x30` modelado | Implementación deliberadamente mínima |
| Lectura SPI `01/10` | **Rechazada como no implementada** | No podemos afirmar un arranque de sesión completo |
| Instalación en Stadia retail HAB CLOSED | **No demostrada** | La ruta de firmware personalizado sigue pendiente |
| Reconocimiento efectivo por Switch 2 | **No demostrado** | Compatibilidad oficial solo del mando auténtico |

Los binarios `bootloader-usb-acm(1).bin` (`18D1:946B`, CDC) y `thebb_ivt_flashloader.bin` (`15A2:0073`, HID) se han inspeccionado solo estáticamente: ninguno declara la identidad USB del Pro NS1.

## Próximo trabajo medible

1. Construir una capa de **respuestas SPI/calibración sintéticas**, con datos públicos no identificables, y ampliar los subcomandos `0x01/0x21`.
2. Contrastar toda la secuencia contra una **captura USB completa y verificable** de un Pro NS1 auténtico funcionando con Switch 2; no confundir un handshake parcial con compatibilidad final.
3. Separar la viabilidad del protocolo de la cuestión de **ejecutabilidad del firmware personalizado en RT1061 HAB CLOSED**. Ni el candidato CDC ni el flashloader HID prueban esa vía.

**Seguridad:** no enviar USB Vendor, no ejecutar SDP, no escribir firmware, no modificar eFuses, no usar el bonding store privado. Las pruebas están basadas en tramas sintéticas y modelos de host/dispositivo, no en instrucciones de ROM ni en una consola física.
