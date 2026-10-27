# Fase 80 — Correlación pasiva de operaciones USB por URB/IRP

**27 de octubre de 2026.** Extensión offline de la [fase 79](auditoria-usb-pasiva-fase79.md). No requiere mando conectado. Se preserva la compatibilidad con CSV anteriores y el anclaje SHA-256 del descriptor físico de la fase 61.

## Hallazgo metodológico

Los eventos de host `S` (envío) y `C` (finalización), o `S` y `E` (error), pueden pertenecer a la **misma operación USB**. Wireshark expone `usb.urb_id` y, en ciertos registros USBPcap de Windows, `usb.irp_id`. El analizador ahora correlaciona esos identificadores **en memoria**, distinguiendo:

- Pares `S→C` y `S→E` con el mismo identificador y endpoint.
- `C/E` sin `S` previo y `S` todavía pendiente al final de la captura.
- Identificador reutilizado después de cerrar una operación: válido para contar otro par.
- Repetición del mismo identificador antes de cerrarse: ambigüedad, nunca se atribuye un par.
- Discrepancia de endpoint y filas sin identificador/endpoint: nunca se atribuye un par.

Los identificadores de URB/IRP **no se escriben en el resultado ni en mensajes de error**; solo se publican contadores. Se admiten números enteros sin signo de hasta 64 bits en decimal o `0x` hexadecimal. Si una fila contiene ambos identificadores y difieren, se rechaza. El contador de pendientes se limita a 200 000 entradas para evitar agotamiento de memoria.

## Uso diferido con una captura propia

Cuando haya un mando disponible, grabar únicamente actividad normal mediante usbmon/USBPcap, manteniendo local el `.pcapng`. Exportar metadatos:

```sh
tshark -r local/stadia-normal.pcapng -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e usb.bus_id -e usb.device_address -e usb.endpoint_address -e usb.urb_type -e usb.data_len -e usb.bmRequestType -e usb.setup.bRequest -e usb.idVendor -e usb.idProduct -e usb.urb_id -e usb.irp_id > local/stadia-metadata.csv
python -m tools.audit_passive_usb_phase79 local/stadia-metadata.csv --bus <bus_real> --address <direccion_real> --out local/phase80.json
python -m unittest tests/test_passive_usb_phase80.py -v
```

Comprobar que la versión de Tshark instalada reconoce ambos campos; si uno no existe, omitir solo su `-e`. Si ninguno se exporta, el análisis conserva su funcionamiento anterior y registra `not_exported`. Los identificadores son locales a la captura y **pueden reutilizarse**: el emparejamiento solo sirve como control de coherencia, no como prueba de comandos ejecutados por el dispositivo.

No subir capturas, metadatos brutos ni identificadores de host al repositorio. El análisis **no envía comandos al mando, no conoce el contenido de los reportes y no cambia el firmware**.

## Estado y límites

**Confirmado mediante implementación y pruebas sintéticas:** reglas de correlación y descarte de asociaciones ambiguas. **No confirmado físicamente:** capturas reales, atribución de un endpoint a un receptor OEM firmado, entrada de host a Work Queue, control de callbacks, ejecución arbitraria, firmware propio o bypass de HAB CLOSED.

**GO**: analizar contadores de capturas reales propias y, solo después, mapear receptores OEM con evidencia independiente. **NO-GO**: inferir recepción o ejecución por contar URBs correlacionados.

Referencias: [Wireshark USB](https://wiki.wireshark.org/USB) · [Campos USB de Wireshark](https://www.wireshark.org/docs/dfref/u/usb.html) · [Linux usbmon](https://docs.kernel.org/usb/usbmon.html).

[Código](../../tools/audit_passive_usb_phase79.py) · [Pruebas sintéticas](../../tests/test_passive_usb_phase80.py)
