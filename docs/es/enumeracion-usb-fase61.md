# Fase 61 — Enumeración física USB y límite de la vista WinUSB

**26 de octubre de 2026.** Medición de un mando conectado, en modo USB normal `18D1:9400`. Se continúa el experimento recomendado por la fase 60. No se ha leído la aplicación instalada ni comprobado su hash; esta fase no vuelve a consultar su build.

## Resultado medido

La consulta al hub padre devuelve un descriptor de configuración de **80 bytes**, configuración 1, con **dos interfaces**, ambas en alternate setting 0:

| Interfaz | Clase USB/subclase/protocolo | Endpoints declarados | Paquete máximo |
|---|---|---|---|
| 0 | `FF/00/00`, fabricante | bulk IN `0x87`, OUT `0x07` | 512 bytes |
| 1 | `03/00/00`, HID | interrupt IN `0x83`, OUT `0x03` | 64 bytes |

El descriptor HID declara un report descriptor de **182 bytes**; no se ha obtenido ese descriptor crudo. Las capacidades interpretadas por Windows confirman input de 11 bytes, ID3; output de 5 bytes, ID5, dos valores de 16 bits; y ningún feature report declarado. Una salida declarada no prueba vibración ni que cualquier valor sea aceptado por el firmware.

## Hallazgo metodológico: WinUSB devuelve una vista parcial

`WinUsb_GetDescriptor` sobre MI_00 devuelve **32 bytes**, una interfaz y los dos endpoints bulk. El descriptor de dispositivo coincide entre esa vista y el hub. Consultar el hub mediante `IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION` devuelve **80 bytes**, incluyendo las dos asociaciones de interfaz, HID y sus endpoints. Se preservan ambas respuestas exactas en la evidencia. Este contraste se ha medido en este equipo; no se atribuye a todos los controladores o versiones de Windows.

La lectura WinUSB por sí sola habría omitido HID. Por ello no debe emplearse como censo completo del dispositivo compuesto. Microsoft documenta la [consulta de descriptores al hub](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ni-usbioctl-ioctl_usb_get_descriptor_from_node_connection) y la [estructura de petición](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ns-usbioctl-_usb_descriptor_request); la pila impone GET_DESCRIPTOR estándar, dirección dispositivo→host.

## Consecuencias para las hipótesis

- **Confirmado:** el mando actual declara bulk `0x07/0x87`, coincidentes en dirección y tamaño con los endpoints reconstruidos en el bootloader. Esto no identifica qué callback o parser usa la aplicación actual; el bootloader y la aplicación son contextos distintos.
- **Acotado:** esta configuración declara clases USB `0xFF` y `0x03`, sin interfaz de clase USB `0x0A`. El **selector interno 10** reconstruido en el firmware no debe confundirse automáticamente con `bInterfaceClass=0x0A`. La enumeración no demuestra ni refuta que ese selector se use internamente.
- **Sin resolver:** lectores/invocadores de `0x2000FBF4/0x2000FBF8`, configuración interna `owner+4/+8/+12`, entrada USB hasta un callback, control del puntero y ejecución propia. El NO-GO de fase 60 sigue vigente.
- **No probado:** elusión HAB, escritura de firmware propio o compatibilidad nativa con Switch 2/Xbox.

## Reproducción

En Windows, con un único mando USB conectado y los drivers existentes:

```powershell
./tools/Get-StadiaUsbDescriptors.ps1 -OutFile local/usb-enumeration-phase61.json
./tools/Get-StadiaHidCapabilities.ps1 -OutFile local/hid-capabilities-phase61.json
python tools/parse_usb_configuration.py evidence/usb-enumeration-phase61.json
python -m unittest tests.test_usb_configuration_phase61 -v
```

Crear `local/` si aún no existe. El recolector obtiene el hub/puerto mediante PnP, lee descriptores estándar tipos 1 y 2 índice 0 y omite strings, rutas e identificadores personales en su salida. La apertura WinUSB utiliza el acceso requerido por su inicialización; no llama a transferencias class/vendor, no manda datos bulk ni reportes output. No cambia drivers, modo USB, memoria, firmware o eFuses. No es una captura de enumeración al reconectar ni una medición de SRAM.

[Bytes medidos](../../evidence/usb-enumeration-phase61.json) · [Capacidades HID medidas](../../evidence/hid-capabilities-phase61.json)

## Próximo paso acotado

Comparar offline estos descriptores completos con las tablas candidatas de la aplicación OEM exacta, distinguiendo su imagen de la del bootloader. Para asociar el selector interno 10 se necesita seguir su descriptor/registro en código firmado hasta la configuración que reproduce estas interfaces. La mera coincidencia de endpoints no basta. Si se obtiene una captura USB normal, deberá anonimizarse antes de publicarla; no se ha instalado USBPcap ni provocado una reconexión en esta sesión.
