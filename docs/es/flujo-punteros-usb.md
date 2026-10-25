# Fase 22 — Seguimiento conservador de alias por bloque de instrucciones

**Objeto:** bootloader A build 169429, 131.072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Archivo privado analizado **offline**, sin conectarlo al mando ni subir el binario a GitHub.

## Problema que resolvemos

Las 29 cargas PC-relativas candidatas identificadas en la fase 21 apuntan a
literales que contienen la base RAM `0x20008B78`. Tener la dirección del
objeto no significa que una función pueda alterar los callbacks:
tenemos que seguir el registro que contiene ese puntero y ver qué
instrucciones lo usan antes de perder la información de su procedencia.

La nueva herramienta `tools/audit_alias_dataflow.py` usa Capstone ARM Thumb
para examinar **como máximo 96 bytes por candidato y solo el primer tramo
lineal hasta una llamada, salto o retorno**. Sigue `MOV`, sumas/restas con
desplazamiento inmediato, lecturas `LDR/ LDRB/ LDRH` y escrituras
`STR/ STRB/ STRH` con base conocida. Si un registro queda
sobrescrito con datos desconocidos, deja de tratarlo como alias.

No analiza funciones llamadas, ramas alternativas, alias por pila,
DMA, tablas de salto, otros módulos de firmware ni todos los formatos
de transferencia múltiple. Detener el análisis en esos puntos es una
decisión de seguridad epistemológica, no una conclusión de
inaccesibilidad. Las 29 entradas siguen siendo **candidatos de
desensamblado**, no 29 rutas ejecutadas demostradas.

## Nuevos hallazgos verificados en el original

| Instrucción | Acceso | Campo |
|---|---|---|
| `0x6080978E` | Carga la base global en `R2` | `0x20008B78` |
| `0x60809790` | `STRB.W R3,[R2,#0x6C4]` | Estado `0x2000923C` |
| `0x60809838` | Carga la base global en `R4` | `0x20008B78` |
| `0x60809842` | `STRB.W R3,[R4,#0x6C4]` | Estado `0x2000923C` |
| `0x60809E6A` | `LDR` del global; lectura posterior en `+0x5F0/+0x5F4` | Callback de **eventos vendor** |
| `0x60809EB8` | `LDR` del global; lectura posterior en `+0x6C4` | Estado para configurar endpoints |

Las dos escrituras comprobadas están en **`+0x6C4`**, y no en los
campos `+0x5F8` (IN) o `+0x600` (OUT) que nos interesan para
cambiar la función de finalización de los paquetes.

Además, algunas referencias pasan o conservan alias durante llamadas a
otras funciones. El auditor documenta los registros de argumento
`R0–R3` conocidos en cada llamada y **no** inventa qué hará el destino.
Otros alias pueden viajar en registros preservados, memoria o punteros
derivados sin seguimiento.

## Por qué sigue pendiente el objetivo

Este análisis **no puede demostrar ausencia de escrituras** sobre los
callbacks: examina un único prefijo por candidato. Su informe
identifica accesos con base conocida, tramos detenidos y punteros que
pueden escapar, pero no proporciona un grafo completo de flujo de datos
ni un camino desde USB.

No se ha identificado un setter de callback accesible desde el host,
ni una ruta USB `0x07` → parser → escritor flash, ni un bypass de
**HAB CLOSED**. Tampoco se ha ejecutado firmware propio.

## Reproducción sin hardware

```powershell
py -m pip install -r requirements.txt
py tools/audit_alias_dataflow.py local/bootloader-a.bin --out local/fase22.json
py -m unittest discover -s tests -v
```

El SHA-256 exacto se comprueba antes de interpretar la imagen. CI usa
imágenes sintéticas en las que se insertan lecturas, escrituras a campos
diferentes, copias de registros, aritmética de punteros, llamadas y saltos.
No se necesitan controladores USB ni se realiza ninguna operación física.

## Fase 23 propuesta

Profundizar selectivamente en los **alias que llegan a llamadas**,
identificar posibles funciones que reciben una referencia al objeto y
comprobar sus escrituras mediante un grafo de flujo de datos
interprocedimental de alcance explícito. También conviene separar los
canales de actualización reales del firmware y verificar el orden de
autenticación de las imágenes. La prioridad continúa siendo evitar
cualquier experimento que pueda inutilizar el único mando.