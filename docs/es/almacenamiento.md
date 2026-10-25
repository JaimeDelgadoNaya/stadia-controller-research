# Almacenamiento y emulación acotada — fase 11

[English](../en/storage.md) · [Traspaso completo](traspaso.md)

Alcance: análisis estático del mismo build/hash y emulación aislada. En esta fase
no se accedió al mando, escribió flash física ni ejecutó firmware nuevo.

## El descriptor 0x12 corresponde al IVT compartido

El constructor global `0x6080BAC0` recibe el objeto agregado con base
`0x20008B78`. El fragmento `0x6080BD50..0x6080BDCA` construye el descriptor ID
`0x12`, con objeto de almacenamiento en base+`0xA78` (`0x200095F0`), primer
bloque 1 y cantidad de bloques 1. `0x6080BD8E` carga la tabla de almacenamiento
sin cifrado `0x60815300`; `0x6080BD94` la guarda en el objeto.

El dispositivo está en base+`0x3BC` (`0x20008F34`). Su constructor recibe
base+`0x2C`; las escrituras en offsets relativos `0x394` y `0x398` fijan tamaño
y cantidad de bloques del dispositivo a `0x1000` cada uno. Sus offsets base
y de primer bloque son cero. El traductor físico `0x60808A50` suma
`0x60000000` al offset de flash.

La traducción de `0x6080AA66` queda así:

```text
offset_flash = (primer_bloque_partición - primer_bloque_dispositivo) * tamaño_bloque
               + offset_base_dispositivo + offset_partición
             = (1 - 0) * 4096 + 0 + offset_partición
dirección = 0x60000000 + offset_flash
```

Con offset de partición cero, el descriptor `0x12` corresponde a **`0x60001000`**,
con tamaño de **4096 bytes**, coincidiendo con las direcciones de autenticación.

## Métodos virtuales resueltos

| Offset en tabla `0x60815300` | Destino | Función inferida del código |
|---|---|---|
| `0x00` | `0x6080AB4C` | Borrado; delega cantidad de bloques |
| `0x04` | `0x6080AB10` | Lectura |
| `0x08` | `0x6080B0F0` | Escritura |
| `0x0C` | `0x6080B036` | Comprobación de contenido/borrado |
| `0x10` | `0x6080AFE4` | Consulta de alineación/geometría |
| `0x14` | `0x6080AA3C` | Consulta de cantidad de bloques |

La tabla del dispositivo físico es `0x60815320`. Sus destinos son lectura
`0x60808ACC`, borrado `0x60808C00`, escritura `0x60808E38` y traducción de
dirección `0x60808A50`. El borrado recorre bloques usando su tamaño configurado.
No se auditaron exhaustivamente el controlador ni los fallos de alimentación.

## Segunda observación aritmética y sus límites

La comprobación compartida `0x6080AA7C` calcula `offset + longitud` en 32 bits y
lo compara con `bloques_partición * tamaño_bloque_dispositivo`. El escritor la
llama antes de traducir el offset y delegar en el dispositivo físico.

`tools/emulate_storage.py` ejecuta el escritor, la comprobación, el traductor y
la consulta de bloques en un emulador ARM aislado. Construye un objeto IVT con
la geometría trazada estáticamente. **El escritor físico se intercepta y simula
un resultado satisfactorio; nunca se ejecuta.** Los casos fuera de límites se
detienen en la rama de diagnóstico, sin emular el registro de mensajes ni
afirmar un código final de error.

| Invocación sintética | Delegación observada |
|---|---|
| Argumentos IVT reales: offset 0, longitud `0x1000` | Offset flash `0x1000`, mismo origen y longitud |
| Offset `0x1000`, longitud 1 | Rama de error; sin llamada al escritor físico |
| Offset 0, longitud `0x1001` | Rama de error; sin llamada al escritor físico |
| Offset `0xFFFFFFF0`, longitud `0x10` | Offset flash `0xFF0`, longitud `0x10`, delegado al escritor simulado |

El último caso demuestra **delegación fuera de partición en un contexto
construido**, no escritura real. El llamador IVT revisado suministra offset cero
y longitud fija `0x1000`, no ese offset sintético. No se han demostrado control
externo de esos parámetros, aceptación del dispositivo, corrupción de memoria
ni elusión de firmas. Escribir flash y conseguir ejecución autenticada son
problemas distintos: cruzar una partición no resuelve por sí solo HAB.

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_storage.py
python -m unittest discover -s tests -v
```

Los cuatro casos están en [storage-emulation.json](../../evidence/storage-emulation.json).
