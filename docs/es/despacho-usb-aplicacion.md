# Despacho USB de aplicación y reubicación ITCM

[English](../en/application-usb-dispatch.md)

La muestra privada Bruce de SHA verificado permite reconstruir una ruta estática
condicional hasta el [receptor HID de dos canales de etiqueta 5](funcion-mensaje-aplicacion.md).
No demuestra un comando ejecutado desde el host, escritura de firmware ni ejecución propia.

## Direcciones de ejecución corregidas

El arranque copia `0xBDF8` bytes desde la dirección de imagen `0x6004081C` a ITCM
en cero. La rutina almacenada en `0x600429BC` (offset de archivo `0x29BC`) se
ejecuta, por tanto, en **`0x000021A0`**. Las llamadas relativas deben decodificarse
con ese PC de ejecución: la llamada de rearme en `0x21F8` va al trampolín ITCM
`0xB610`, que carga el destino XIP `0x600D5400`.

La copia de datos inicializados coloca el dato de imagen `0x6013E058` en RAM
`0x200031F0`, con callback Thumb `0x21A1`. La función `0x6006262C` devuelve esa
dirección de configuración. Esto vincula la rutina reubicada con un registro
inicializado, sin medir su registro ni ejecución en vivo.

## Ruta condicional

La tabla TBB asigna el **evento interno 2** al bloque `0x21D6`. Es un identificador
interno de evento/finalización, no un opcode USB enviado por el host. Con el byte
global `0x2000A33C` distinto de cero, obtiene el búfer y la longitud de los campos
0 y 4 del evento. La longitud `0xFFFFFFFF` es un centinela que evita invocar el callback.

La llamada indirecta `0x21F4` utiliza los campos función/contexto de
`0x200064C0+0x3950/+0x3954`, iguales a `0x20009E00+0x10/+0x14`. El wrapper
`0x60058BDC` instala directamente el thunk `0x600D3687` y el parser `0x60058B65`.
El thunk adapta los argumentos y salta al receptor de etiqueta 5 en `0x60058B64`.

**Corrección del registro:** el helper `0x600D543C` copia otra pareja de
callback/contexto al objeto **+8**, no +0x10. La pareja del receptor se instala
mediante las escrituras directas posteriores del wrapper. Son campos distintos.

Después de la invocación condicional, el despacho rearma mediante `0x600D5400`,
con argumento de endpoint **3** y longitud **64**, y llama a `0x600D0E38`. Estos
argumentos no demuestran por sí solos la dirección del endpoint, la semántica del
descriptor HID ni la fuente física del evento. No se envió ningún informe de
salida ni paquete manipulado al mando.

## Reproducción

```sh
python tools/audit_app_usb_dispatch.py local/bruce_pvt_a_prod_signed.bin
python -m unittest tests.test_app_usb_dispatch -v
```

El auditor exige el SHA completo y el análisis anterior de etiqueta 5; después
comprueba literales de arranque, huellas de regiones, instrucciones con PC
reubicado y alias de punteros. La [evidencia saneada](../../evidence/application-usb-dispatch.json)
no contiene la imagen propietaria. Pasaron cuatro pruebas sintéticas de mapeo,
límites y rechazos, además de la ejecución real del auditor sobre la muestra.

Este resultado no establece un receptor genérico de comandos vendor, acceso a
escritura flash, elusión de firmas, parche instalable ni compatibilidad Switch 2.
