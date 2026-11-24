# Fase 101 — mando Stadia virtual interactivo (24/11/2026)

**Objetivo:** integrar los resultados de fases 93–100 en una simulación visible y reproducible de un mando ficticio; en particular distinguir ROM pública RT1060 de BootROM RT1061 *real* aún no caracterizada. **No ejecutar el exploit sobre hardware**.

## Entregable

**[Abrir código del laboratorio HTML autónomo](../../research/phase101/stadia_virtual.html).** Archivo de una sola página, sin librerías ni dependencias remotas: mando Stadia dibujado en CSS, botones A/B/X/Y + cruceta, control de estados, registro de eventos y dos perfiles.

Los archivos Python completos `virtual_stadia.py`, `test_virtual_stadia.py`, `smoke_ui.js`, escenarios JSON y el HTML se distribuyen asimismo en el paquete descargable de la conversación `Stadia_Mando_Virtual_Fase101.zip`.

**Pruebas realmente ejecutadas en el entorno de trabajo:**
- **30/30** pruebas del núcleo Python con `python -m unittest -q test_virtual_stadia.py`.
- **8/8** aserciones de estados de interfaz JavaScript en DOM simulado con Node.js; `node --check` sin errores.
- Escenario **Stadia observado**: ROM SDP y HAB CLOSED como hechos previos; no hay copia de BootROM interna; intento ROMC => bloqueo; no admite imagen unsigned ni ejecución.
- Escenario **RT1060 hipotético**: usa como **SUPUESTOS**, no como hallazgos, compatibilidad de ROM y efectos de la cadena de explotación. Permite avanzar por parche ROMC virtual, imagen de prueba de 8192 bytes sin CSF, intérprete del marcador ARM de fase 97 `0x5A` en RAM virtual, botones de interfaz (NO driver ARM), y reinicio que borra parche y marcador.

## Evidencias del proyecto reutilizadas

1. ZIP `nxp-sdp-overrun-main.zip` recibido del propietario y abierto directamente el 24/11/2026, SHA-256 `fbaae33730aa1fb959843c9531abcc436fa50f04c1d082215e4bae0753521908`; `main.py` SHA-256 `e41e659f25388578ef9b2c1a1800adecf9e290d5ec0b57fbabb8705c3f765404`. La rama por defecto `SHELLCODE_ROMC` restaura puntero USB y parchea una respuesta HAB; la rama `FIELD_RETURN` programa eFuse y es irreversible.
2. [Fase 100](bootrom-dinamica-e-imagen-ram-fase100.md): ejecución real en **emulador Unicorn** de un tramo acotado del callback HID de la BootROM pública RT1060: longitudes 2048 aceptadas, 2049 rechazadas; puntero de recepción `0x2020723F`. No simula EHCI/USB completo ni toda la cadena ROMC/HAB.
3. [Fase 97](firmware-ram-fase97.md): binario ARM Thumb propio de 20 bytes, SHA-256 `68a75935017e47c373d2df0b9294c31781705894511bc62fea78b6a265806f38`, escribe marcador `0x5A` en RAM **solamente en intérprete aislado**. No implementa GPIO, HID, USB ni BLE.
4. [Mediciones previas](mediciones.md) del 25/10/2026: modo ROM SDP `1FC9:0135`, familia RT106x `0x006C0000`, HAB CLOSED. No se obtuvo la ROM interna ni versión exacta.
5. La imagen IVT/Boot Data sin CSF de fase 100 es un **artefacto hipotético**, no una imagen autorizada por HAB ni una carga verificada en el dispositivo.

## Matriz de interpretación

| Fase en el mando virtual | Perfil observado | Perfil de ROM RT1060 hipotética |
|---|---|---|
| Encender / SDP / HAB CLOSED | Datos medidos previamente | Estado de partida del modelo |
| Informe HID 2048 | Basado en referencia, **no probado en Stadia** | Comportamiento modelado de ROM RT1060 |
| ROMC temporal | **BLOQUEADO** | Se supone éxito, sin cambiar fuses |
| Imagen unsigned en RAM | Rechazada | Admitida solo por supuesto |
| Marcador `0x5A` | No ejecutado | Sí en intérprete RAM ficticio |
| Botones de mando | Interfaz de demostración, no driver ARM | Interfaz de demostración, no driver ARM |
| Reiniciar | Sin cambio de HAB | Patch y RAM desaparecen |

**No afirmar:** emulación completa del i.MX RT1061, ejecución de la cadena de exploit, HAL/ROMC/SJC fidelizados, evidencia nueva de RT1061, bypass HAB real, modo Xbox real o firmware personalizado persistente.

## Investigación pública adicional del 24/11/2026

El autor del exploit, `tchebb`, declaró el 14/11 que lleva un port Zephyr y firmware personalizado en marcha, **todavía no listo para publicar**. El 16/11 otro participante declaró persistencia tras `FIELD_RETURN`, procedimiento irreversible y excluido:
https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/

No se localizó un release verificable del port Zephyr Stadia al cierre de la fase. No confundir con puentes software tipo Stadiacast, que no cargan firmware propio en el procesador.

## Próximo hito

Identificar de modo verificable la BootROM **interna** de la unidad RT1061 (revisión de máscara y ROM/HAB), o disponer del port público del autor. Solo entonces evaluar un protocolo de prueba temporal **recuperable** en hardware de laboratorio, sin tocar `FIELD_RETURN`/OTP y sin flashear la unidad única.

**Todo el desarrollo 101 se realizó sin conectar mando físico y sin tráfico USB ni escritura persistente.**
