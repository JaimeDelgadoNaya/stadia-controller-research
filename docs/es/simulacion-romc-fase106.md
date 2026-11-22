# Fase 106 — Intentos de obtención de nxp-sdp-overrun y simulación ROMC (22/11/2026)

## Resultado de la descarga

**No se pudo descargar el repositorio original** https://codeberg.org/tchebb/nxp-sdp-overrun. Se probaron Git y TAR (desde el contenedor: DNS no resuelve codeberg.org), acceso web (restricción de acceso) y API. GitHub devuelve 404 para github.com/tchebb/nxp-sdp-overrun. No se encontró espejo auténtico con el código fuente. No atribuir a este trabajo una auditoría o ejecución del exploit original.

## Nueva fuente secundaria relevante

Se inspeccionó el repositorio independiente [gomezluisj/stadia-controller-re](https://github.com/gomezluisj/stadia-controller-re/tree/67e58b14b1b863ca7654408a2676baf3dbdc59e5) en el commit exacto `67e58b14b1b863ca7654408a2676baf3dbdc59e5` (19/11/2026). Sus documentos [bare-metal-bringup.md](https://github.com/gomezluisj/stadia-controller-re/blob/67e58b14b1b863ca7654408a2676baf3dbdc59e5/docs/bare-metal-bringup.md) y [boot-and-nor.md](https://github.com/gomezluisj/stadia-controller-re/blob/67e58b14b1b863ca7654408a2676baf3dbdc59e5/docs/boot-and-nor.md) describen **según su autor**:

- Desbordamiento de tres bytes en el dispatcher HID de la ROM SDP i.MX RT1060, descubierto por tchebb y utilizado para una sesión ROMC; no se inspeccionó el exploit original.
- Firmware bare-metal ejecutado temporalmente en un Stadia PVT H2B, sin modificar NOR ni eFuses, con USB CDC-ACM y lectura de entradas.
- Restricción de hardware: DMA USB1 no puede acceder a DTCM; buffers de USB deben alojarse en OCRAM.
- La vía ROMC es temporal: **no equivale a instalar firmware permanente**, y no demuestra que FIELD_RETURN sea reversible o seguro.

No se ha realizado reproducción propia en una unidad Stadia.

## Simulación propia (se adjunta ZIP por separado en la conversación)

Modelo `virtual_stadia_phase106.py` de **mando ficticio**: imagen original firmada, entrada SDP supuesta, inyección explícita de estado de desbloqueo temporal (nunca se ejecuta el exploit), marcador RAM ficticio, control de DMA y reinicio que regresa al firmware original. Prohíbe cualquier escritura NOR/eFuse y el intento de FIELD_RETURN.

- **24 pruebas locales correctas**, 0 fallos; una prueba contiene **500 sesiones aleatorias**.
- HAB CLOSED ficticio rechaza RAM unsigned normal.
- La sesión ROMC **inyectada por el laboratorio** acepta un marcador no ejecutable solo mientras dura la sesión. Tras reset, se restaura el estado cerrado.
- DTCM falla para USB DMA, OCRAM pasa en el modelo.
- FIELD_RETURN / flasheo de bootloader CDC / escritura NOR: NO-GO.
- No hubo ROM real emulada, USB físico, imagen ARM ejecutada, firmware Xbox instalado ni modificación persistente.

**Próxima evidencia necesaria:** copia auténtica (commit + SHA) del código de tchebb para auditoría estática, y verificación de cualquier ejecución temporal sin escritura en hardware recuperable. La instalación retail sigue sin vía segura demostrada.

**Fuentes adicionales:** [NXP SPSDK sdphost](https://spsdk.readthedocs.io/en/v3.4.1/usage/applications.html), [recurso previo fase105](ruta-sdp-overrun-field-return-fase105.md).
