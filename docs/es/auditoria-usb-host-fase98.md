# Fase 98 — Auditoría USB HID y prueba del reloj de reportes

**22/11/2026 · investigación Stadia → Switch 2.** Ejecución completamente offline. No se conectan mandos ni consolas, se ejecuta firmware o se modifican memorias, eFuses o KVS.

## Correcciones reales al simulador anterior

El modelo de fase 97 respondía a `0x80 01`, `0x80 02` y `0x80 03` con 10, 2 y 2 bytes respectivamente, mientras que el descriptor de referencia USB NS1 Pro declara **reportes `0x81` de 64 bytes**. También rechazaba las peticiones `0x80` correctamente rellenadas con ceros hasta 64 bytes. Se corrigieron ambos problemas en `tools/simulate_switch_pro_phase97.py` y sus tests: respuestas de 64 bytes, aceptación de padding cero y rechazo de padding no nulo o tamaños superiores.

## Descriptor HID de referencia: 203 bytes

Fuente: [HIDMaestro / profiles/nintendo/switch-pro-usb.json](https://github.com/hifihedgehog/HIDMaestro/blob/master/profiles/nintendo/switch-pro-usb.json) (blob Git `0b1646a3694a72fa135f17e89773a85ff98e131f`). El autor documenta que el descriptor procede de una captura de Pro NS1 auténtico. El descriptor tiene **203 bytes**, SHA-256 `25f0b3b7e59bdfec05e8cced16e43a8878509865a0cb223f05025c556f3bedba`.

Un parser estático de elementos HID **sin USB real** confirma:

| Dirección | ID | Tamaño del reporte completo |
|---|---|---:|
| INPUT | `0x21`, `0x30`, `0x81` | 64 bytes |
| OUTPUT | `0x01`, `0x10`, `0x80`, `0x82` | 64 bytes |

No aparece `0x3F` en el descriptor USB de referencia. No debe inferirse que los modos simples Bluetooth y USB son idénticos. La procedencia declarada por un tercero no equivale a una captura propia ni a una captura de Switch 2. Otros antecedentes: [dekuNukem USB-HID-Notes](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/master/USB-HID-Notes.md), [HIDMaestro INTERNALS](https://github.com/hifihedgehog/HIDMaestro/blob/master/docs/INTERNALS.md), [espp NS1 USB](https://esp-cpp.github.io/espp/hid/switch_pro.html).

## Filtro estructural de hardware

El nuevo `tools/audit_switch_pro_host_phase98.py` comprueba VID:PID, interfaz HID, interrupt IN/OUT y longitudes de reportes. No emite descriptores reales en un dispositivo físico.

| Muestra | Identidad USB | Resultado |
|---|---|---|
| Bootloader Stadia A original | `18D1:946B` | No pasa el filtro Pro NS1 |
| Candidato bootloader Stadia CDC | `18D1:946B` | No pasa el filtro Pro NS1 |
| Flashloader RAM comunitario | `15A2:0073` | No pasa el filtro Pro NS1 |
| Perfil **inventado** con descriptor de referencia NS1 | `057E:2009` | Pasa solo la estructura de datos |

La tabla no demuestra que el hardware no pueda cambiar su identidad si algún día se ejecuta firmware distinto; demuestra que **los binarios recibidos no presentan hoy ese perfil**. Una simulación con `057E:2009` en memoria no cambia nada en el mando.

## Prueba de reportes periódicos

Se añadió un reloj virtual de ensayo de **15 ms**, valor descrito por implementaciones comunitarias USB y **no medido ni validado en Switch 2**.

- Tras `80 01/02/03/04`, pero **antes** del subcomando `0x03` que selecciona modo `0x30`, nuestro simulador no genera entradas en una ventana simulada de 45 ms. Esto es una **laguna funcional potencial**, no una prueba de rechazo por Switch 2.
- Una vez negociado `0x30`, genera **tres reportes `0x30` de 64 bytes en 45 ms virtuales**. No hay temporizadores reales ni transporte USB.
- Las tres respuestas iniciales `0x81` son ahora de 64 bytes y la respuesta al cambio de modo `0x21` también es de 64 bytes.
- El descriptor público no declara `0x3F`, por lo que el simulador no inventa reportes simples para ocultar el hueco de inicialización.

## Pruebas

**15 pruebas nuevas** de fase 98, más 19 de fase 97 y 54 de las fases anteriores: **88 pruebas locales sin fallos**. Incluyen pruebas negativas de IDs, endpoints, reporte truncado, tamaños inválidos, formato de `0x81` y secuenciación periódica.

GitHub Actions: [regresión completa](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45066787388), Python 3.11 y 3.12: **1.131 pruebas descubiertas por versión, 35 omitidas, 1.096 superadas y ninguna fallida**.

Datos auditables: `evidence/switch-pro-usb-host-phase98.json`. Tests: `tests/test_switch_pro_host_phase98.py` y los corregidos `tests/test_switch_pro_phase97.py`.

## Bloqueos siguientes

1. Conseguir una **captura USB completa e independiente** de un mando Pro NS1 genuino conectado a Switch 2: enumeración, endpoints, reportes y temporización. La fuente externa aporta un descriptor de referencia, no esa captura.
2. Resolver de manera independiente el **arranque seguro** de código personalizado en i.MX RT1061 comercial HAB CLOSED. Los binarios recibidos no demuestran una vía segura de instalación.
3. No utilizar `FIELD_RETURN`, SDP, modificaciones flash o fusibles para contrastar una simulación que todavía es incompleta.

**Decisión:** continuar con pruebas de host, detección de tiempo muerto y cotejo de fuentes; no afirmar que Switch 2 reconoce físicamente al mando de Stadia.
