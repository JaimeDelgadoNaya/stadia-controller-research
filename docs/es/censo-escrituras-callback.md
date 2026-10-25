# Fase 20 — Censo estático de escrituras candidatas en callbacks USB

**Muestra:** bootloader A Google Stadia, build 169429, 131.072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Análisis realizado **offline** sobre el fichero privado, sin conectar ni
modificar el mando. La imagen original no se publica.

## Qué queríamos comprobar

En la fase 19 reconstruimos la inicialización de cuatro campos del
objeto de la interfaz USB del fabricante:

| Campo | Dirección RAM | Offset respecto a `0x20008B78` | Instrucción inicial |
|---|---|---|---|
| Callback Bulk IN `0x87` | `0x20009170` | `+0x5F8` | `0x6080BB50` |
| Contexto Bulk IN | `0x20009174` | `+0x5FC` | `0x6080BB6C` |
| Callback Bulk OUT `0x07` | `0x20009178` | `+0x600` | `0x6080BB5A` |
| Contexto Bulk OUT | `0x2000917C` | `+0x604` | `0x6080BB70` |

Los callbacks iniciales siguen siendo `0x6080AFFA` y
`0x6080AFFC`, dos funciones `BX LR` que retornan inmediatamente.

Buscamos pistas de **una posible sustitución posterior** de esos campos.
Un verdadero «setter» exigiría demostrar su código, que recibe un puntero al
objeto correcto y cuándo es invocado. Un patrón de bytes por sí solo no
demuestra nada de esto.

## Censo reproducible en el binario verificado

El script `tools/audit_callback_writers.py` examina el intervalo de bytes
`0x60801000..0x60814F00` (exclusivo) como **candidatos Thumb de media palabra
alineada**, sin afirmar que cada posición sea una instrucción alcanzable.
Detecta específicamente la codificación de `STR.W Rt,[Rn,#imm12]`
con desplazamiento positivo.

| Desplazamiento buscado | Coincidencias | Ubicación |
|---|---:|---|
| `0x5F8` (callback IN) | 1 | `0x6080BB50` |
| `0x5FC` (contexto IN) | 1 | `0x6080BB6C` |
| `0x600` (callback OUT) | 1 | `0x6080BB5A` |
| `0x604` (contexto OUT) | 1 | `0x6080BB70` |

En esos cuatro casos, la instrucción es `STR.W` con base `R4`,
ya identificada en el constructor `0x6080BAC0`.

Tampoco aparecen **punteros absolutos alineados de 32 bits** a ninguna
de las cuatro direcciones RAM buscadas en toda la imagen de 128 KiB.

Una segunda búsqueda en `0x60809E24..0x6080A076` inspecciona
`STR` Thumb de 16 bits y `STR.W` Thumb-2 de desplazamiento
positivo `+0x10,+0x14,+0x18,+0x1C` (campos relativos al propio
objeto vendor `0x20009160`). **No aparecen coincidencias** en
este intervalo de bytes para esas formas específicas.

## Interpretación correcta del resultado

**No hemos identificado un setter posterior de los callbacks con las
codificaciones y direcciones inspeccionadas. Esto NO demuestra que tal
setter no exista.** Quedan fuera, entre otras posibilidades:

- Direcciones derivadas por suma, alias de punteros o desplazamientos
  parciales que acaben accediendo a los mismos campos.
- `STRD`, `STM`, escrituras indirectas o instrucciones con otros
  modos de direccionamiento.
- Funciones situadas fuera de los intervalos examinados, caminos de
  ejecución no reconstruidos y posibles escrituras DMA.
- Código en aplicaciones o regiones distintas al bootloader examinado.

Además, un barrido de bytes alineados puede reconocer como instrucción
lo que en realidad sea un literal o dato. La nueva herramienta **no
realiza un análisis de flujo de datos o de alcanzabilidad completo**.
Por eso no afirma que la ausencia de una coincidencia descarte una
actualización legítima del firmware.

## Reproducción segura

```powershell
py tools/audit_callback_writers.py local/bootloader-a.bin --out local/fase20.json
py -m unittest discover -s tests -v
```

El analizador comprueba el SHA-256 integral y las anclas de instrucciones
del constructor antes del barrido. Las pruebas usan únicamente una imagen
**sintética**; no se ha subido el binario original.

## Próxima investigación

La fase 21 debe priorizar **el flujo de punteros**, no repetir más
búsquedas de un único opcode: identificar qué funciones reciben la
dirección del objeto vendor, resolver escrituras indirectas sobre
`+0x10/+0x18` y buscar otros caminos de recepción y validación.
Para poder afirmar un comando de actualización USB hay que reconstruir
el trayecto desde el host y sus comprobaciones de firma.

**Estado:** ninguna ruta USB externa al escritor flash demostrada,
ninguna elusión de HAB CLOSED, ninguna ejecución de firmware propio.
