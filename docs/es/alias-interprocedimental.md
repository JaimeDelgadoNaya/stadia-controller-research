# Fase 23 — Alias entre funciones: llamadas directas y subobjetos

**Muestra verificada:** bootloader A Stadia build 169429, 131.072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.

La fase se ha desarrollado **offline** con la copia privada del bootloader;
no se ha conectado el mando ni publicado firmware propietario.

## Pregunta que se aborda

En la fase 22 algunas rutas se detenían al llegar a una llamada.
Ahora seguimos **solo llamadas directas con instrucciones y argumentos
anclados** para reconstruir cómo se entrega el objeto global
`0x20008B78` a distintas funciones. No se hace un grafo de
alcanzabilidad general, una ejecución simbólica completa ni una
simulación de comandos enviados desde el host.

## Cuatro entradas comprobadas

Cada entrada carga `R0` desde un literal que contiene `0x20008B78`
y ejecuta un `BL` cuyo destino se decodifica de los bytes ARM Thumb.

| Carga de global | Llamada | Función destino | Interpretación |
|---|---|---|---|
| `0x6080C0B2` | `0x6080C0B4` | `0x6080BAC0` | Constructor ya auditado |
| `0x60802502` | `0x60802504` | `0x6080B218` | Servicio del objeto global |
| `0x60808136` | `0x60808138` | `0x6080B218` | Otro acceso al mismo servicio |
| `0x6080FB4A` | `0x6080FB4C` | `0x6080B17C` | Inicialización de subobjetos |

Son **relaciones directas de código**, no cuatro comandos USB disponibles.

## Hallazgo: cuatro subobjetos diferentes

`0x6080B17C` guarda la base global en `R4` mediante
`MOV R4,R0`. Después prepara argumentos derivados de esa base
para cuatro llamadas directas, siempre que las llamadas precedentes
retornen normalmente:

| Instrucción de llamada | Argumento R0 | Función llamada |
|---|---|---|
| `0x6080B186` | global `+0x568` | `0x6080A990` |
| `0x6080B18E` | global `+0x560` | `0x608022A0` |
| `0x6080B196` | global `+0x630` | `0x6080990C` |
| `0x6080B19E` | global `+0x578` | `0x60809D98` |

La última referencia corresponde al objeto que en fases anteriores
asociamos con el código de USB CDC; eso **no prueba que CDC esté activo
en el dispositivo**.

También comprobamos que `0x6080B218` transforma `R0` en
`global+0x630`, y ejecuta un salto directo `B.W` desde
`0x6080B21C` a `0x60809ABC`. En este último destino se suma
`+0x14` antes de la primera llamada en `0x60809AC2`
a `0x60809688`. Por tanto, el argumento derivado es
**global `+0x644`** si se sigue ese camino normal.

## Qué cambia respecto a la fase 22

Hemos convertido algunos de los límites de llamada pendientes en
relaciones de argumentos y destinos **reproducibles**. Los offsets
de los subobjetos descritos son diferentes de los campos
de callback IN `global+0x5F8` y OUT `global+0x600`.

**Esto NO descarta que el código de una función llamada pueda acceder
a esos callbacks con otra dirección calculada.** El análisis actual
se detiene en los destinos que no se han inspeccionado y no asegura
que las llamadas se ejecuten en un estado concreto del hardware.

Seguimos sin demostrar un registro posterior del callback Bulk OUT,
un parser de mensajes externo, una ruta USB→escritura flash o la
elusión de HAB CLOSED.

## Implementación y reproducción

El nuevo `tools/audit_interprocedural_aliases.py` comprueba
el SHA-256 exacto, literales del objeto global, instrucciones
de copia/arimética y destinos de `BL`/`B.W` decodificados.
La suite incluye **16 pruebas sintéticas** que no contienen firmware
original y se ejecuta sin acceder al USB.

```powershell
py tools/audit_interprocedural_aliases.py local/bootloader-a.bin --out local/fase23.json
py -m unittest discover -s tests -v
```

## Fase 24 — Continuación propuesta

Revisar **selectivamente los cuerpos** de
`0x6080A990`, `0x608022A0`, `0x6080990C` y
`0x60809D98` con seguimiento limitado de escrituras a memoria.
Después contrastar cualquier candidato a setter con su procedencia,
su estado de registro y las verificaciones de autenticación.
No realizar pruebas físicas mientras no exista una vía recuperable.
