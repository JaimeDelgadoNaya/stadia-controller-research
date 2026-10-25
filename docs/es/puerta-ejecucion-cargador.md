# Cargador firmado original: bloqueo de Execute y Call

La inspección offline del `restricted_ivt_flashloader.bin` original (100.672 bytes;
SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`)
identifica funciones Execute y Call, pero **su despacho normal las rechaza antes
de invocarlas**. No se ha enviado ningún comando al mando para esta comprobación.

El arranque copia `0x830` bytes desde `0x200164D8` a `0x20208000` mediante
`0x2000247E..0x20002490`. El global inicializado `0x202081F4`, campo `+0x10`,
apunta a `0x202081E4`; el campo `+8` de esa interfaz selecciona la tabla
`0x20015978`, con entradas de 12 bytes.

El despachador `0x20002EB4` obtiene el tag del mensaje en `0x20002EF4`,
comprueba 1..21 y calcula su entrada. En `0x20002F0A` lee el byte `+8`:
si es cero, sustituye la entrada por NULL. La rama `0x20002F2C` responde
con estado genérico `0x2710` (10000) y el tag original. El salto al handler
mediante `BLX R3` en `0x20002F1A` requiere entrada y handler habilitados.

| Comando | Tag | Entrada | Handler Thumb | Habilitado |
|---|---|---|---|---|
| Execute | `0x09` | `0x200159D8` | `0x200033A1` | 0 |
| Call | `0x0A` | `0x200159E4` | `0x2000340D` | 0 |
| ReadMemory | `0x03` | `0x20015990` | `0x200035A5` | 1 |
| WriteMemory | `0x04` | `0x2001599C` | `0x200030D9` | 1 |

Este bloqueo ocurre antes de comprobar la dirección propuesta y es distinto
de GetProperty `0x11`: su caso `0x20009AF0` llama a `0x2000A87C`, que extrae
el bit 1 de OCOTP_CFG5 (`0x401F4460`) y lo normaliza a 0/1. La propiedad
informa del estado; no constituye una opción de desbloqueo.

La tabla está en RAM: proceder de una imagen firmada no la hace físicamente
inmutable. Se trazó la fase de datos WriteMemory (`0x20003250`) hasta el backend
`0x20003B7C`, que comprueba la política `0x200039A8` con operación 2 antes de
delegar al mapa genérico de memoria. Sus cuatro rangos inclusivos, inicializados
en `0x2020826C` desde el offset `0x16744` de la imagen, son:
`0x2000..0x21FF`, `0x60000000..0x60000FFF`, `0x60001000..0x60001FFF`
y `0x60004000..0x60FFFFFF`.

Una escritura ordinaria de longitud positiva sin desbordamiento sobre los bytes
de habilitación `0x200159E0` o `0x200159EC` queda excluida con estado `0x27D8`
antes de la copia RAM. Que el mapa genérico incluya RAM no elimina esta política
previa.

El backend recibe el tamaño de cada **fragmento**, no la longitud total declarada:
`0x200031EC..0x200031FE` calcula el mínimo entre bytes restantes y tamaño recibido;
`0x20003244..0x20003250` llama al backend con ese tamaño. La tabla de lectura
USB `0x20015F38`, referenciada en `0x20016124`, contiene el método Thumb
`0x20004EF5`. En `0x20004F5E..0x20004F78`, el receptor construye el tamaño con
dos bytes de cabecera y comprueba que cabe en la transferencia recibida menos
cuatro bytes. Por tanto, el tamaño que alcanza la política es como máximo 65535,
independientemente de una longitud total enorme. Es una cota conservadora; no
afirma que se acepten informes USB de ese tamaño. No puede desbordar al sumarlo
a `0x200159E0` o `0x200159EC`: la hipótesis concreta de habilitar esas entradas
mediante longitud total desbordada no funciona por esta ruta USB intacta.

Otras rutas de mutación, transportes, estados corruptos y efectos generales de
desbordamiento quedan fuera del alcance. El modelo rechaza sumas desbordadas.
ReadMemory no se ha trazado exhaustivamente en este paquete.
No se ha probado ejecución propia, recuperación ni compatibilidad directa con
consolas. Tampoco se descarta otra vulnerabilidad, corrupción de estado, otro
cargador firmado u otra ruta de ejecución.

```sh
python tools/audit_loader_execution_gate.py local/restricted_ivt_flashloader.bin
python -m unittest discover -s tests -p test_loader_execution_gate.py -v
```

El auditor verifica tamaño/hash de toda la imagen, instrucciones seleccionadas,
punteros de inicialización y entradas de comandos. Las pruebas usan datos
sintéticos. [Evidencia publicable](../../evidence/loader-execution-gate.json).
No emula el receptor completo ni demuestra accesibilidad desde mensajes
malformados arbitrarios. [Detalle en inglés](../en/loader-execution-gate.md).

## Límite de la conclusión para otros comandos

La tabla también habilita FillMemory. El límite por fragmentos de WriteMemory
no se puede aplicar a FillMemory ni a otras órdenes sin revisar sus propios
receptores y backends. Su presencia no demuestra ejecución propia; este auditor
no proporciona ni valida una elusión a través de ellas.

## Seguimiento: FillMemory

La [revisión independiente de FillMemory](analisis-fillmemory.md) comprueba la hipótesis de una política distinta a la de WriteMemory. El comando está habilitado y utiliza un patrón de 32 bits sin fase de datos, pero **no se ha ejecutado todavía la inspección nueva contra la muestra binaria original**. No hay demostración de sobrescritura de memoria de control, ejecución propia o recuperación fiable.
