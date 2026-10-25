# Actualización del IVT y validación ARM aislada — fase 10

[English](../en/update-flow.md)

Esta fase analiza el mismo bootloader extraído, build 169429. No accede al mando
ni ejecuta actualizaciones persistentes. Las direcciones y descripciones se
aplican únicamente al hash registrado. Los nombres de métodos de almacenamiento
se infieren de argumentos y mensajes; falta trazar las implementaciones concretas.

## El callback comprueba alimentación y una entrada física

El llamador en `0x608028B4` carga el puntero `0x6080285D` y lo pasa a
`0x60801ED0` desde `0x608028C6`, con el contexto `0x200090D8`. El constructor
`0x60801CC8` guarda el callback y su argumento. La llamada indirecta en
`0x60801E58` termina así en el salto Thumb `0x6080285C`, que deriva a `0x608022FC`.

`0x608022FC` llama primero a `0x608021B4`. Esta función referencia
`lightweight_power_manager.cc`, «Issues reading voltage» y «Voltage is», obtiene
un valor de 16 bits y lo compara con `0x0D4C` (3404). No se han trazado por
separado sus unidades ni conversión. Un resultado no nulo detiene la operación.
Si devuelve cero, el callback lee un bit de entrada de hardware y devuelve su
inverso como booleano. Falta identificar la entrada física exacta.

Este callback es una comprobación, no una función que copie toda la imagen
candidata. Su dirección procede de una constante en el llamador trazado; no se
ha demostrado que un usuario externo pueda controlar ese puntero.

## Selección explícita del bootloader actual y candidato

`0x60801DD4` llama a `0x60807E64`, que consulta la entrada IVT compartida de
`0x60001004`. La rama posterior, para el identificador actual `0x03`, selecciona
la base candidata `0x60820000` y el descriptor `0x13`; para el actual `0x13`,
selecciona `0x60800000` y el descriptor `0x03`. Son identificadores de partición
de bootloader, no una afirmación sobre los identificadores de aplicación.

Primero se autentica el bootloader actual. Después se comprueba estructuralmente
el candidato opuesto, como se documentó en la fase 9. B vacío no proporciona
vectores válidos, por lo que no debe interpretarse como un respaldo utilizable
de inmediato. No se instaló ni modificó ningún candidato.

## Buffers del IVT, tamaños fijos y restauración

El contexto selecciona el descriptor de almacenamiento `0x12`. Los mensajes
identifican la operación como instalación del IVT. Este es el flujo observado:

| Paso | Evidencia | Valor o acción |
|---|---|---|
| Conservar el IVT existente | `0x60801E36..0x60801E42` | Llamada de lectura: buffer `0x200029C8`, offset 0 y longitud `0x1000` |
| Seleccionar descriptor candidato | `0x60801E4A..0x60801E50` | Descriptor del bootloader opuesto en la tabla |
| Comprobar condiciones | `0x60801E54..0x60801E5C` | El callback de alimentación/entrada debe devolver cero |
| Leer IVT candidato | `0x60801D9C..0x60801DAE` | Llamada de lectura: buffer `0x200019C8`, offset 0 y longitud `0x1000` |
| Instalar IVT candidato | `0x60801D40..0x60801D98` | Métodos de preparación/consulta y llamada de escritura con offset 0 y longitud `0x1000` |
| Autenticar después | `0x60801E80..0x60801E8C` | Validador del candidato con bandera de autenticación 1 |
| Intentar restauración en fallos pertinentes | `0x60801E9A..0x60801EA2` | Mismo escritor IVT con el buffer preservado `0x200029C8` |

Si falla la lectura del IVT candidato, devuelve `0x0A` antes de escribir; existe
una salida anticipada específica para ese resultado. Otros fallos de instalación
y los de autenticación posterior llevan hacia la restauración. Esto demuestra
que existe lógica de restauración, **no** garantiza recuperación ante pérdida de
alimentación o fallos del almacenamiento. No se ha verificado la granularidad
física de borrado ni todo el comportamiento de esa implementación.

Las llamadas de lectura/escritura revisadas reciben una longitud fija de
**4096 bytes**. No se ha encontrado que la longitud boot-data examinada por la
función aritmética sustituya ese argumento. Por ello, la observación de rangos
no demuestra por sí sola una copia del IVT de tamaño excesivo.

## La aritmética se reproduce ahora con instrucciones reales

La evidencia pública contiene los 36 bytes originales de la función `0x60801FE6`,
SHA-256 `29d8988e80bc7a4292ead2e4c029ae437ce0f7220eb66962f10a2c0c3a3eb3ce`.
`tools/emulate_range_check.py` comprueba esa huella y ejecuta únicamente esos
bytes en un emulador Unicorn ARM/Thumb M-class limitado, con memoria aislada.

Los ocho casos coinciden con el modelo Python. Las instrucciones reales aceptan
el rango desbordado y una longitud cero que empiece dentro del intervalo.
Rechazan los casos normales fuera de límites que se probaron. Los resultados
y conteos de instrucciones figuran en [range-emulation.json](../../evidence/range-emulation.json).

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_range_check.py
python -m unittest discover -s tests -v
```

Esto demuestra la aritmética de la función aislada; no demuestra que sea
aprovechable en el programa completo, escritura arbitraria, ejecución en el mando
ni elusión de firmas.

## Siguiente límite por resolver

Resolver los métodos virtuales de almacenamiento y el destino concreto del
descriptor `0x12`; después, comprobar si metadatos boot-data malformados pueden
afectar a algo más que la validación preliminar. Cualquier vía de ejecución
propuesta tendrá que explicar cómo supera la autenticación y los tamaños fijos.
