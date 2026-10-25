# Bruce: seguimiento offline de las solicitudes USB de clase 0x81 / 0x83 / 0x84

**25/10/2026 · PR #32 · solo lectura.**

## Qué se intenta comprobar

El JavaScript OEM archivado, cuya identidad ya se verificó en la fase
anterior, envía desde el PC al mando en modo normal `18D1:9400`:

| Petición del host | Tipo/API observados | Uso en el actualizador |
|---|---|---|
| `0x81` | USB control IN, clase/interfaz | Leer build/versión |
| `0x83` | USB control OUT, clase/interfaz | Preparar lectura de batería |
| `0x84` | USB control IN, clase/interfaz | Leer batería |

**Pregunta de investigación:** ¿podemos enlazar por código esos
`bRequest` de USB con funciones concretas del Bruce original
y, más allá de las consultas, con algún receptor que permita ejecución
de código propio o actualización no firmada?

## Auditoría reproducible

`tools/audit_bruce_class_requests.py` exige el tamaño de
**1.050.984 bytes** y el SHA-256
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`
del archivo público Bruce original, idéntico a la muestra anteriormente
aportada. No utiliza USB/HID y no modifica archivos.

El auditor verifica las dos referencias a
`usb_device_vendor.cc` (`0x60061504` y `0x600615B4`);
inspecciona ventanas de código próximas y, además, realiza un
**censo de comparaciones con inmediatos** en los bytes de la
aplicación firmada. En la sección inicial copiada a ITCM, los PCs
impresos son **direcciones de origen**, no direcciones de ejecución.

### Resultados del censo Thumb lineal

| Valor | Comparaciones encontradas | Interpretación |
|---|---:|---|
| `0x81` | **2** | Una compara el primer byte de un búfer; otra aparece tras una `TBB` y puede proceder de datos de tabla |
| `0x83` | **1** | Contexto con decodificación lineal dudosa; no constituye handler confirmado |
| `0x84` | **5** | Comparaciones de campos en estructuras internas; no se ha demostrado que sean `setup.bRequest` |

**Ocho coincidencias no equivalen a ocho comandos ni a ocho receptores.**
El barrido es lineal y puede decodificar tablas/literales como
instrucciones; además, no cubre selectores basados en tablas,
restas de base, llamadas indirectas ni valores procesados en RAM.
No es un grafo de control alcanzable desde USB.

### 0x81 en `0x60070C54`

Se verificaron en la imagen auténtica estas instrucciones:
`0x60070C4C: LDRB R3,[R1]`,
`0x60070C50: CMP R3,#0x30`,
`0x60070C54: CMP R3,#0x81`, y la rama
`0x60070C6C` lee `[R1,#1]`.
Otra rama procesa `[R1,#3]` y `[R1,#5]`, extrayendo bits y
actualizando campos de estado de una estructura.

Este código **interpreta un búfer de datos con etiquetas 0x30/0x81**.
No hemos identificado la procedencia de `R1` desde la estructura
`usb_setup_packet`, ni enlazado la llamada al control transfer
del navegador. Por tanto, **no se puede llamar al byte 0
«bRequest USB 0x81»**. Puede ser un protocolo de mensajes
totalmente diferente.

### 0x84 en `0x600F4B44`

La ruta fija a las instrucciones
`0x600F4B40: LDRB.W R3,[R3,#0x32]`,
`0x600F4B44: CMP R3,#0x84` y
`0x600F4B4E: CMP R3,#2`. La comparación se hace contra
un **campo de estructura desplazado `+0x32`**, acompañada de
otras comprobaciones de estado. No existe enlace probado a
`setup.bRequest=0x84` del actualizador.

### Referencias al componente vendor

Las dos referencias literales a
`usb_device_vendor.cc` están en rutas de registro de
mensajes/formateo. **Una referencia a una etiqueta de archivo fuente
no identifica la función receptora de las peticiones USB**.
No se han localizado en esas ventanas comparaciones inequívocas
de `bRequest` con `0x81/0x83/0x84`.

## Estado y criterio de avance

| Premisa | Estado |
|---|---|
| Peticiones USB 0x81/0x83/0x84 en el actualizador host | Verificadas en JS archivado |
| Código original Bruce / SHA-256 | Verificado |
| Candidatos de comparaciones Thumb | Inventariados, no necesariamente ejecutables |
| `bRequest` físico → receptor Bruce | **No trazado** |
| Receptor → carga de código propio | **No trazado** |
| Bypass HAB CLOSED o recuperación | **No demostrados** |
| Compatibilidad Xbox / Switch 2 directa | **No conseguida** |

Para cerrar esa cadena sería necesario demostrar
**la procedencia de los campos de un SETUP packet dentro del firmware,
la función registrada para EP0/interfaz clase y su vinculación con el host**.
Una captura USB de las consultas **de solo lectura** podría corroborar
el transporte, pero no demostrar por sí sola un receptor ejecutable.

No está justificado seguir generando hipótesis a partir de
coincidencias de un byte ni enviar comandos desconocidos o
de escritura al único mando.

## Reproducción

```sh
python -m unittest tests.test_bruce_class_requests -v
python -m tools.audit_bruce_class_requests local/bruce_pvt_a_prod_signed.bin --preview
```

El workflow `signed-app-host-boundary.yml` utiliza una copia
temporal del original con identidad SHA verificada y elimina el
archivo al terminar. No se ejecuta el actualizador, no se abre
el navegador y no se envían paquetes al dispositivo.

[PR #32 y verificación original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/32).
