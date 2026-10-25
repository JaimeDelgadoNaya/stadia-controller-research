# Fase 19 — Destinos iniciales de los callbacks USB Bulk IN y OUT

**Objeto:** bootloader A Stadia, build 169429, **131072 bytes**, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Esta fase es **offline**. El binario privado continúa fuera del repositorio; no
se ha conectado el mando, enviado comandos, ejecutado código propio ni escrito flash.

## Resultado principal: ambos callbacks empiezan como funciones vacías

La fase 18 estableció que Bulk IN `0x87` registra el adaptador
`0x60809E30` y Bulk OUT `0x07` registra `0x6080A06A`. Esta fase
sigue los argumentos del adaptador y la inicialización del objeto al que apuntan.

La pila USB `0x60806660` almacena un puntero de callback y su
**contexto** en la entrada del endpoint. Cuando una finalización es entregada
por la rutina `0x60806554`, esta recupera ambos y realiza `BLX` en
`0x60806558`. Para OUT, `0x6080A06A` mueve el contexto (`R2`)
a `R0` y llama a `0x6080A062`. Allí se leen:

- Puntero de función desde **`[R0+0x18]`**.
- Contexto de esa función desde **`[R0+0x1C]`**.
- Salto indirecto `BX R3` en `0x6080A068`.

El objeto del fabricante se construye en
`0x20008B78 + 0x5E8 = 0x20009160`. La rutina constructora
`0x6080BAC0` prepara las dos parejas función/contexto:

| Endpoint | Campo función RAM | Campo contexto RAM | Literal usado | Función inicial |
|---|---|---|---|---|
| Bulk IN `0x87` | `0x20009170` | `0x20009174` | `0x6080BBB4` | `0x6080AFFA` |
| Bulk OUT `0x07` | `0x20009178` | `0x2000917C` | `0x6080BBB8` | **`0x6080AFFC`** |

Ambos contextos se inicializan con cero. Los literales contienen punteros
Thumb impares: `0x6080AFFB` (IN) y `0x6080AFFD` (OUT).

**Ambas funciones contienen únicamente los bytes `70 47`, instrucción
ARM Thumb `BX LR`.** El destino inicial de las notificaciones de
finalización se limita a retornar; no analiza los datos del paquete.

## Direcciones e instrucciones que enlazan las piezas

| Dirección | Comprobación estática |
|---|---|
| `0x6080BB3C` | Instala la vtable del objeto fabricante |
| `0x6080BB50` | Guarda puntero IN en offset global `+0x5F8` |
| `0x6080BB5A` | Guarda puntero OUT en offset global `+0x600` |
| `0x6080BB6C` | Contexto IN = 0 en offset global `+0x5FC` |
| `0x6080BB70` | Contexto OUT = 0 en offset global `+0x604` |
| `0x6080BB7C` | Construye puntero a objeto vendor, global `+0x5E8` |
| `0x60809F16` | Pasa callback de endpoint y objeto como contexto |
| `0x60806554`–`0x60806558` | Recupera e invoca callback registrado |
| `0x6080A062`–`0x6080A068` | Reenvía el evento al puntero del objeto |
| `0x6080AFFA` y `0x6080AFFC` | Rutinas iniciales `BX LR` |

Una búsqueda limitada de la **secuencia exacta** de cuatro bytes de
`STR.W R3,[R4,#0x600]` encuentra una aparición en `0x6080BB5A`.
Esto **no** es una auditoría exhaustiva de todas las escrituras a RAM:
un setter posterior podría usar otras instrucciones, registros o punteros.

## Consecuencia práctica y límites

La ruta de **finalización Bulk OUT `0x07` en su estado inicial** es inerte.
No se ha probado que el firmware no pueda reemplazar el callback durante la
ejecución, ni que otras interfaces USB o rutas de actualización estén inactivas.
La presencia de un endpoint no equivale a disponer de un parser de comandos.

**No existe prueba de un recorrido USB externo → escritor flash ni de
elusión HAB CLOSED o ejecución de firmware propio.**

## Reproducir el análisis sin el dispositivo

`tools/audit_vendor_completion.py` exige el SHA-256 integral conocido,
comprueba **ocho regiones** de instrucciones con huellas independientes, los
literales/vtables y los bytes de los dos handlers, y emite JSON saneado.
Los tests de CI utilizan imágenes sintéticas.

```powershell
py tools/audit_vendor_completion.py local/bootloader-a.bin --out local/fase19.json
py -m unittest discover -s tests -v
```

No subir a GitHub el binario o los informes que puedan contener datos personales.

## Próxima investigación: fase 20

Buscar llamadas o escrituras que pudieran **sustituir los callbacks** en
`0x20009170` y `0x20009178`, identificar interfaces de registro y
rastrear la procedencia de los bytes USB hasta cualquier parser real.
Separar cambios de callback demostrados de simples coincidencias en desensamblado.
