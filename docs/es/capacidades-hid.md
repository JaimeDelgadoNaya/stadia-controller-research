# Capacidades HID medidas del mando conectado

El **25 de octubre de 2026** se consultó de nuevo el mando USB `18D1:9400`
mediante las API HID de Windows. La evidencia saneada está en
[`evidence/stadia-hid-capabilities.json`](../../evidence/stadia-hid-capabilities.json).
No contiene rutas de dispositivo, números de serie ni identificadores de instancia.

## Resultado actual

| Elemento | Declaración del dispositivo interpretada por Windows |
|---|---|
| Colecciones superiores | Una, página `0x01`, uso `0x05` (gamepad) |
| Entrada | Report ID `3`, máximo de 11 bytes incluyendo ID |
| Controles de entrada | 18 capacidades de botón: 15 de página `0x09` y 3 de página `0x0C`; 7 capacidades de valor |
| Valores de entrada | Hat de 4 bits; cuatro ejes de 8 bits; dos valores de página `0x02`, usos `0xC4/0xC5`, de 8 bits |
| Salida | Report ID `5`, máximo de 5 bytes incluyendo ID |
| Valor de salida | Página `0x0F`, uso `0x97`, **dos elementos de 16 bits**, rango lógico `0..65535` |
| Feature | Longitud declarada cero y ninguna capacidad devuelta |

La salida declarada equivale a **4 bytes de carga más un byte de ID** y
corrobora el contrato de informe 5 del análisis offline. Es evidencia de su
forma, no de la semántica del receptor: esta consulta no envió el informe ni
demuestra por sí sola vibración, acceso de memoria o ejecución de código.

## Reproducción

Desde la raíz del repositorio, con el mando conectado en modo USB normal:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/Get-StadiaHidCapabilities.ps1
```

Para conservar una medición local nueva sin sustituir la evidencia publicada:

```powershell
New-Item -ItemType Directory -Force local | Out-Null
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/Get-StadiaHidCapabilities.ps1 -OutFile local/hid-capabilities.json
```

La herramienta enumera interfaces HID presentes, filtra `18D1:9400`, comprueba
atributos y abre cada colección con `CreateFile` **desiredAccess=0**. Consulta
`HidD_GetPreparsedData`, `HidP_GetCaps`, `HidP_GetValueCaps` y
`HidP_GetButtonCaps`; libera recursos al terminar. Si no hay colección coincidente,
devuelve `collection_count: 0`; eso no constituye una medición del contrato.
No incluye API de envío de informes, cambios de modo o modificaciones de firmware.

## Alcance de la API

Windows entrega capacidades interpretadas a partir de sus datos preparsed.
**No se extrajo aquí el descriptor HID crudo** y no deben presentarse estos
resultados como una captura de bytes de entrada/salida. Las longitudes de
`HIDP_CAPS` incluyen el ID y son máximos por clase de informe.
[Definición de HIDP_CAPS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidpi/ns-hidpi-_hidp_caps).

`ReportCount` y `BitSize` de `HIDP_VALUE_CAPS` describen el número de elementos
y su tamaño, respectivamente; de ahí la observación `2 × 16 bits` para la salida.
[Definición de HIDP_VALUE_CAPS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/hidpi/ns-hidpi-_hidp_value_caps).

Esta medición corresponde al mando conectado y su estado actual; no prueba que
todos los builds Stadia publiquen el mismo contrato. La combinación con el
descriptor histórico y el análisis del receptor debe conservar esas procedencias
por separado.
