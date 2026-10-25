# Fase 14 — Configuración USB y callback del fabricante, con binario verificado

Se ha analizado **offline** el bootloader A original, build 169429, 131072 bytes, con
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
El archivo propietario permanece privado y **no** se incorpora al repositorio.
El análisis no implica consultas al mando, escrituras, arranque ni flasheo.

## Hallazgo 1: dos interfaces USB definidas en el bootloader

El descriptor USB Device está en `0x6080BF78`: Google VID `18D1`, PID
`946B`, clase de dispositivo `EF/02/01`, USB 2.0 y EP0 de 64 bytes.
La configuración en `0x6081527C` ocupa **80 bytes** y declara **dos interfaces**:

| Dirección | Interfaz / descriptor | Evidencia |
|---|---|---|
| `0x6081528D` | Interfaz 0, clase de fabricante `FF` | Dos endpoints |
| `0x60815296` | `0x87`, bulk IN, paquete 512 bytes | Descriptor EP |
| `0x6081529D` | `0x07`, bulk OUT, paquete 512 bytes | Descriptor EP |
| `0x608152AC` | Interfaz 1, HID `03` | Dos endpoints |
| `0x608152B5` | Descriptor HID, informe de **156 bytes** | Descriptor HID |
| `0x608152BE` | `0x83`, interrupt IN, paquete 64 bytes | Descriptor EP |
| `0x608152C5` | `0x03`, interrupt OUT, paquete 64 bytes | Descriptor EP |

El puntero de la configuración se encuentra en el literal `0x6080AF54`,
consumido por instrucciones en `0x6080AF48` que entregan puntero y longitud
`0x50`. Son descriptores presentes en la imagen; la configuración efectiva
depende también de la ejecución del USB stack y del estado del hardware.

## Hallazgo 2: controlador de eventos del fabricante

- En `0x60816290` hay un puntero Thumb a `0x60809E64`, la rutina de eventos
  de la clase USB del fabricante. Otra tabla, en `0x60816284`, contiene
  `0x60809C59`.
- La rutina `0x60809E64` exige que el evento recibido (`r1`) sea **mayor
  que `0x7F`** antes de consultar el callback registrado. En esa ruta carga
  `r3 = [0x20008B78 + 0x5F0]` y contexto
  `r0 = [0x20008B78 + 0x5F4]`, y realiza `BLX r3` si el puntero
  difiere de la función por defecto.
- El constructor `0x6080BAC0`, en `0x6080BB46`, inicializa el
  campo `+0x5F0` con la función por defecto Thumb `0x60809E3D`;
  la función `0x60809E3C` simplemente devuelve cero.
- No se ha identificado de forma completa **quién instala otro callback**,
  cómo se parsean los paquetes bulk recibidos, ni si un camino alcanza
  las rutinas de escritura de flash.

Estas observaciones corresponden a **instrucciones y punteros reales** del
binario coincidente, no a un modelo sintético.

## Herramienta reproducible sin mando conectado

`tools/audit_usb_callbacks.py` exige el SHA-256 específico antes de
interpretar direcciones, valida todas las longitudes de los descriptores,
extrae los endpoints y compara instrucciones seleccionadas del callback.
El único resultado es JSON. No abre USB, no ejecuta firmware y no escribe
en ningún dispositivo.

```powershell
py tools/audit_usb_callbacks.py local/bootloader-a.bin --out local/fase14.json
py -m unittest discover -s tests -v
```

La carpeta `local/` está excluida de Git. Las pruebas de CI usan únicamente
datos **sintéticos**; no se publica el firmware.

## Próxima hipótesis verificable

Seguir los posibles registros posteriores en el campo RAM
`0x20009168`, localizar el receptor bulk OUT `0x07` y
vincularlo con un despachador de comandos, **si existe**. Después comprobar
procedencia de longitud/offset, protección HAB y tratamiento de errores
antes de considerar cualquier efecto sobre memoria flash.

**No se ha demostrado acceso USB al escritor, elusión de firmas ni ejecución
de firmware personalizado.**
