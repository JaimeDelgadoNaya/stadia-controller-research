# Fase 18 — Descriptores RAM e identificación definitiva del callback Bulk OUT

**Muestra:** bootloader A Stadia, build **169429**, 131.072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.

Se analizó **sin conexión al mando** el binario privado verificado. El fichero
original **no se publica**. Los hechos corresponden al flujo normal de arranque
del firmware; no se ha medido memoria RAM del mando en ejecución.

## Avance: del código de arranque a los endpoints en RAM

La inicialización a partir de `0x60801600` copia palabras de 32 bits de
flash a RAM. Los literales de `0x60801694/98/9C` fijan el intervalo:

| Elemento | Dirección |
|---|---|
| Fuente en flash | `0x608161E0` |
| Destino RAM inicial | `0x20000000` |
| Final RAM, exclusivo | `0x20000190` |
| Total copiado | **400 bytes** |

El bucle usa `LDRLT R0,[R1],#4` y `STRLT R0,[R2],#4`, y repite mientras el
puntero de destino sea inferior al límite. El flujo alternativo de arranque
en `0x608015C4` puede saltarse esta inicialización; la conclusión se refiere
a la ruta normal.

Dentro de esos 400 bytes, en `0x608162B8`, están exactamente los registros
compactos:

```text
87 02 00 02   07 02 00 02
```

Cada registro contiene dirección USB (1 byte), atributos (1 byte) y tamaño
máximo de paquete (2 bytes, little-endian). Corresponden a los dos descriptores
USB estándar presentes en `0x60815296` y `0x6081529D`.

## Relación completa con los callbacks registrados

La rutina `0x60809EB8` obtiene el puntero `0x200000DC` mediante el literal
`0x60809F90`. En la primera iteración toma el registro ubicado en
`R4-4 = 0x200000D8`. La función de registro `0x60806660` recibe esos datos
junto al callback seleccionado mediante `R6=0` desde la tabla
`0x60814F24`. Después `0x60809F70` incrementa `R4` cuatro bytes y
`0x60809F7E` pone `R6=1` para la segunda iteración.

| Iteración | Inicializador flash | Registro RAM | Endpoint | Tabla callbacks | Callback destino |
|---|---|---|---|---|---|
| 0 | `0x608162B8` | `0x200000D8` | **Bulk IN `0x87`** | `0x60814F24` | `0x60809E30` |
| 1 | `0x608162BC` | `0x200000DC` | **Bulk OUT `0x07`** | `0x60814F28` | **`0x6080A06A`** |

Esta correspondencia está respaldada por la **copia RAM inicial, los
registros compactos, los descriptores USB, los bytes de las instrucciones
y la tabla de callbacks**. Resuelve explícitamente la incógnita de fase 17.

Con el modelo de registros de la pila USB (`0x60806660`), OUT `0x07`
se coloca en el índice 14 e IN `0x87` en el 15.

## Qué ocurre después del callback OUT

El adaptador `0x6080A06A` mueve `R2` a `R0` y llama a
`0x6080A062`, que carga una función desde `[R0+0x18]`, su contexto
desde `[R0+0x1C]` y salta indirectamente en `0x6080A068`.

**Aún no hemos resuelto cuál es la función final** ni la procedencia del
contenido del paquete, ni un analizador de órdenes de host, ni una ruta
USB → escritura flash. HAB CLOSED sigue activo y no existe una elusión de
firmas ni ejecución de firmware personalizado demostrada.

## Herramienta reproducible

`tools/audit_endpoint_ram_init.py` verifica primero el hash completo del
bootloader y **seis regiones** mediante hashes independientes. Comprueba
instrucciones de copia, literales de fuente/destino, orden de registros,
descriptores USB y callbacks. Genera JSON saneado, exclusivamente a partir de
un fichero local. Las pruebas automatizadas emplean únicamente una imagen
**sintética**; el binario original está excluido de Git.

```powershell
py tools/audit_endpoint_ram_init.py local/bootloader-a.bin --out local/phase18.json
py -m unittest discover -s tests -v
```

## Próxima tarea (fase 19)

Seguir el origen de los campos `+0x18/+0x1C` del contexto de recepción y
resolver el salto indirecto que realiza `0x6080A062`. Solo si se identifica
una ruta real de paquetes de host hacia un parser podremos evaluar controles
de tamaño, autenticación HAB y accesibilidad del escritor de flash.

**Durante la fase 18 no se ha modificado el mando ni ejecutado ninguna
operación de firmware.**