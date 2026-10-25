# Fase 16 — Procedencia de callbacks: CDC frente a interfaz del fabricante

**Binario analizado:** bootloader A build 169429, 131072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
El análisis se efectuó **offline** sobre la copia privada del propietario.
El binario no se distribuye ni se agrega al repositorio.

## Hallazgo 1 — El método de 512 bytes corresponde al objeto CDC

La rutina de la fase 15 en `0x60809B28` comprueba
`CMP.W R2, #0x200` (512 bytes).

Ahora sabemos que su puntero Thumb `0x60809B29` aparece como primera entrada
en la tabla que comienza en **`0x60814E18`**. En la inicialización del objeto
`0x6080BAC0`, una carga en `0x6080BB14` toma precisamente ese puntero de tabla
desde el literal `0x6080BBA8`, y en `0x6080BB1C` lo guarda a offset
`+0x578` del objeto de RAM. El código contiene la cadena
`usb_device_cdc.cc` junto a esa tabla y `usb_device_vendor.cc` en
otro bloque posterior.

**Clasificación:** rutina de la tabla del *objeto CDC*, no una rutina
identificada de recepción de paquetes por el endpoint Bulk OUT `0x07` de
la interfaz del fabricante. La presencia de código CDC **no acredita**
que la interfaz CDC esté activa en la configuración USB observada,
que declara interfaces Vendor e HID.

## Hallazgo 2 — Callback CDC: registro inicial nulo

- El constructor establece `R5=0` en `0x6080BACE`; en
  `0x6080BB06`, escribe ese cero en el campo `+0x584`.
- El objeto CDC está en `base + 0x578` y su callback
  `[objeto + 0x0C]` coincide con `base + 0x584`.
- La función `0x60809C44` consulta `[R0 + 0x0C]`, solo ejecuta
  `BLX R3` si es distinto de cero y devuelve cero en otro caso.
- Una rama del evento CDC en `0x60809CE0` construye
  `R0 = base + 0x578` y llama a `0x60809C44` desde
  `0x60809CE4`.

**Conclusión limitada:** el código contiene una vía interna hasta
un callback opcional, inicializado a nulo. No está establecida una
solicitud USB externa concreta que active ese callback ni
una sustitución posterior de su puntero.

## Hallazgo 3 — El callback del fabricante es otro distinto

La tabla de eventos en `0x60816290` apunta a `0x60809E64`:
para eventos mayores de `0x7F`, consulta la función en
`0x20008B78 + 0x5F0 = 0x20009168`, con contexto en `+0x5F4`.
El constructor guarda en ese campo el puntero Thumb por defecto
`0x60809E3D`, que lleva a una rutina de retorno cero.

En una búsqueda de **la forma exacta de instrucción**
`STR.W R3, [R4,#0x5F0]` se localiza una aparición en
`0x6080BB46`. Eso no excluye escrituras con otro registro,
operaciones indirectas, DMA ni otros mecanismos de registro.
**No** hemos demostrado que el puntero jamás se modifique.

## Estado de la investigación

| Enlace | Estado |
|---|---|
| Descriptor USB Bulk OUT `0x07` | Verificado (fase 14) |
| Tabla CDC y llamada indirecta opcional | Verificadas por instrucciones originales |
| Evento del fabricante y callback por defecto | Verificados |
| Paquete Bulk OUT `0x07` → receptor → parser | **No reconstruido** |
| Datos controlables por host → escritor flash | **No demostrado** |
| Superar HAB CLOSED / ejecutar firmware propio | **No demostrado** |

No se han enviado comandos al mando, no se ha accedido al USB y
no se han escrito memoria flash, registros ni fusibles.

## Reproducción

El nuevo script exige coincidencia SHA-256 **antes** de interpretar las
direcciones y produce un JSON saneado. No publica el archivo original.

```powershell
py tools/audit_usb_callback_provenance.py local/bootloader-a.bin --out local/fase16.json
py -m unittest discover -s tests -v
```

La suite de integración automática utiliza únicamente muestras sintéticas.
La carpeta `local/` sigue excluida por Git.

## Próxima acción útil

Analizar el origen de los parámetros del objeto de eventos del fabricante
y localizar el código de recepción y la ruta de entrega de datos del
endpoint `0x07`, con trazas de llamadas y estructura del paquete. Solo
después podremos evaluar si existe un despachador accesible que alcance
alguna función de almacenamiento, y qué comprobaciones le preceden.