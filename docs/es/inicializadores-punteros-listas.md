# Fase 26 — Inicialización de dos punteros y cabeceras de lista

**Muestra:** bootloader A Stadia, build 169429, 131.072 bytes. SHA-256:
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Análisis estático **offline** de la copia privada, sin usar USB ni modificar el mando.

## Hallazgo 1: ambos campos apuntan al mismo subobjeto en el constructor

El constructor `0x6080BAC0` recibe como base de la estructura global RAM
`0x20008B78` y mantiene el puntero en `R4`. La instrucción
`0x6080BAE2` calcula `R3 = R4 + 0x134`. Dos escrituras usan
ese mismo registro:

| Dirección de instrucción | Campo RAM | Contenido inicial |
|---|---|---|
| `0x6080BAEC` (`STR.W`) | `global+0x560 = 0x200090D8` | `0x20008CAC` |
| `0x6080BAF2` (`STR.W`) | `global+0x568 = 0x200090E0` | `0x20008CAC` |
| `0x6080BAE8` (`STRB.W`) | `global+0x570 = 0x200090E8` | **Un byte 0** |

Las instrucciones ancladas y las huellas SHA-256 permiten reproducir
esta relación, sin depender de etiquetas inferidas del desensamblador.
En un barrido limitado de las codificaciones `STR.W Rt,[Rn,#imm12]`
dentro de `0x60801000..0x60814F00`, los offsets `+0x560` y
`+0x568` aparecen una sola vez cada uno, en las dos instrucciones
anteriores. El barrido no contempla alias ni otros modos de escritura.

**Corrección de las fases 24 y 25:** se describió provisionalmente
`global+0x570` como posible origen de un tercer puntero. **No está
demostrado**: el constructor lo inicializa explícitamente mediante
una escritura de **un byte**, no de un puntero de 32 bits. Por tanto, no
debemos atribuir automáticamente ese campo al origen de un objeto
entregado a `0x60809048`. La vía de `0x6080A990` que carga un
puntero desde el inicio del subobjeto `global+0x568` corresponde,
en el estado inicial, a `0x20008CAC`.

## Consecuencia para la función de transferencia `0x60809048`

**Solo si no se han reemplazado esos punteros después**, los parámetros
que se calculan a partir del objeto apuntado son:

| Expresión | Dirección inicial |
|---|---|
| `input+0x6C` | `0x20008D18` |
| `input+0xA4` | `0x20008D50` |
| `input+0xF8` | `0x20008DA4` |
| `input+0x154` | `0x20008E00` |
| `input+0x158` | `0x20008E04` |
| `input+0x15C` | `0x20008E08` |

Estas direcciones iniciales se encuentran antes de los campos de
callbacks USB `0x20009170/74/78/7C`. Eso **no demuestra**
que las funciones llamadas por `0x60809048` carezcan de otros
efectos ni que los campos de punteros no cambien durante la ejecución.

## Hallazgo 2: dos cabeceras de lista auto-referenciales

`0x60810B38` contiene, en la rama con indicador no nulo, dos
llamadas a `0x6081099C`, desde `0x60810B9C` y
`0x60810BA4`. Sus argumentos provienen de un subobjeto con base
`global+0x58C`: primero `+0x10` y después `+0x24`.

Por ello las bases son `global+0x59C = 0x20009114` y
`global+0x5B0 = 0x20009128`.

La rutina de inicialización `0x6081099C` escribe lo siguiente en
cada cabecera `H`:

| Campo | Valor inicial |
|---|---|
| `[H+0]` | 0 |
| `[H+4]` | `H+8` |
| `[H+8]` | `0xFFFFFFFF` (marcador, no puntero) |
| `[H+12]` | `H+8` |
| `[H+16]` | `H+8` |

De esta forma, las dos cabeceras utilizan **referencias a su propia
zona de enlace**, no direcciones obtenidas de paquetes USB. La función
puede modificar posteriormente esos valores cuando se añaden o se
eliminan nodos.

En la ruta de constructor inspeccionada, `0x60810C06` establece
`R1=1` antes de llamar desde `0x60810C1A` al inicializador
`0x60810B38`. Este pasa dicho indicador a `R5` y, al comprobarlo
en `0x60810B70`, entra en el bloque que inicializa las dos
cabeceras. La conclusión es condicional al recorrido de arranque.

## Límites de la investigación

El estado real de RAM no se ha medido. No hemos demostrado que los dos
punteros se mantengan sin cambios durante toda la ejecución, ni que
las listas puedan o no enlazar objetos próximos a los callbacks.
Tampoco hay prueba de una cadena host USB → parser → escritor flash,
bypass de HAB CLOSED ni ejecución de firmware propio.

## Reproducir

```powershell
py tools/audit_pointer_initializers.py local/bootloader-a.bin --out local/phase26.json
py -m unittest discover -s tests -v
```

El auditor lee **solo** el binario privado coincidente, verifica su
SHA-256 íntegro, cinco huellas de regiones y anclas de instrucciones.
Las pruebas de GitHub Actions emplean exclusivamente datos sintéticos,
sin publicar firmware propietario.

**Fase 27 propuesta:** estudiar las posibles reasignaciones de estos
punteros por otros caminos e identificar la procedencia de nodos
dinámicos, manteniendo pruebas únicamente offline y reproducibles.
