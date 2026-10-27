# Fase 79 — Auditoría pasiva USB: trazas de host frente a descriptores OEM

**27 de octubre de 2026.** Continuación acotada de la [fase 78](inicializacion-compartida-workqueue-fase78.md). Se incorpora una herramienta **exclusivamente offline** para clasificar los metadatos de un volcado USB existente, sin comandos al mando, cambios de firmware ni envío de tramas.

## Resultado realmente obtenido

Se ha implementado `tools/audit_passive_usb_phase79.py`, que utiliza el descriptor **físicamente medido** en la [fase 61](enumeracion-usb-fase61.md), cuya copia completa coincide con una tabla OEM firmada en la [fase 62](coincidencia-descriptores-oem-fase62.md). El auditor valida el SHA-256 del descriptor de configuración de **80 bytes** (`01b299fc757c731df8c2de21a953ed8b0fc0c854f6043c178b8cc7588c26e5db`), el VID/PID `18D1:9400` y los cuatro endpoints conocidos:

| Dirección | Interfaz | Tipo | Máximo declarado |
|---|---:|---|---:|
| `0x07` | 0, fabricante `FF` | bulk OUT | 512 |
| `0x87` | 0, fabricante `FF` | bulk IN | 512 |
| `0x03` | 1, HID `03` | interrupt OUT | 64 |
| `0x83` | 1, HID `03` | interrupt IN | 64 |

Se diferencia `S` (submit), `C` (completion), `E` (error), se agrupan peticiones EP0 por tipo estándar/clase/fabricante, dirección y `bRequest`, y se señalan endpoints no declarados. Un evento `S` y uno `C` pueden pertenecer a la **misma operación URB**, por lo que no se suman como transacciones distintas. Las longitudes reportadas son metadatos del capturador, **no prueba de bytes procesados por el firmware**.

**Evidencia de esta fase:** diez pruebas automatizadas **sintéticas**, incluida detección de VID/PID equivocado, captura mixta, descriptor alterado, petición de control incompleta, identificadores ausentes y columnas privadas. **No se ha obtenido ni analizado tráfico físico nuevo.** Se necesita una captura normal pasiva para producir resultados observados.

## Reproducir con una captura propia, local

1. Grabar pasivamente con Wireshark/USBPcap (Windows) o usbmon (Linux) el uso normal de un único mando, **sin mandar peticiones de prueba**. Mantener el archivo `.pcapng` local. Filtrar y anotar el bus y la dirección USB asignados **después** de la enumeración; no asumir que son constantes tras reconectar.
2. Exportar **solo metadatos**, desde una versión de Tshark que admita los campos usados. Ejecutar en PowerShell 7+ o shell con salida UTF-8:

```sh
tshark -r local/stadia-normal.pcapng -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e usb.bus_id -e usb.device_address -e usb.endpoint_address -e usb.urb_type -e usb.data_len -e usb.bmRequestType -e usb.setup.bRequest -e usb.idVendor -e usb.idProduct > local/stadia-metadata.csv
python -m tools.audit_passive_usb_phase79 local/stadia-metadata.csv --bus 1 --address 4 --out local/phase79.json
python -m unittest tests.test_passive_usb_phase79 -v
```

`--bus 1 --address 4` son **ejemplos**, no la dirección del mando examinado. No usar un filtro por VID/PID para descartar el resto de URBs: dichos campos pueden faltar en mensajes posteriores a la enumeración. Seleccionar bus y dispositivo dentro del CSV completo y documentar el origen de esa asignación. El auditor marca `not_observed` si no consta un par VID/PID dentro de los eventos seleccionados: **no afirma identidad positiva**. Un VID/PID contrario produce error.

El programa rechaza columnas fuera de una lista cerrada (por ejemplo `usb.capdata`), no acepta timestamps, seriales ni contenidos de reportes, y publica únicamente totales. No publicar `.pcapng` ni CSV sin revisión manual de privacidad. Las reglas y semántica de URB se basan en la [referencia de campos USB de Wireshark](https://www.wireshark.org/docs/dfref/u/usb.html) y su [documentación de captura USB](https://wiki.wireshark.org/USB).

## Criterio de progreso real

- **GO** para una investigación estática dirigida solo cuando una captura real aporte operaciones reproducibles sobre endpoints activos. Después se podrá buscar el receptor firmado y demostrar causalidad mediante pruebas adicionales.
- **NO-GO** para atribuir un callback de Work Queue a un paquete simplemente porque comparten una función de inicialización: las fases 75–78 no muestran ese vínculo.
- **NO-GO** para afirmar posibilidad de firmware propio, ejecución controlada o Xbox nativa: sigue sin demostrarse una vía autorizable con **HAB CLOSED**.

No se ha iniciado un dispositivo, leído RAM física ni flasheado memoria. Esta fase entrega **instrumentación verificable y un protocolo de adquisición**, no una nueva vía de ejecución.

[Auditor](../../tools/audit_passive_usb_phase79.py) · [Pruebas](../../tests/test_passive_usb_phase79.py) · [Fase 78](inicializacion-compartida-workqueue-fase78.md)
