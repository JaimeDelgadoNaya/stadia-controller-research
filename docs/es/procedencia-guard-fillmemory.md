# FillMemory — valores iniciales y procedencia de la protección dinámica

**Fecha:** 25/10/2026. **Alcance:** análisis estático y modelos puros, **sin**
paquetes USB/HID, escritura RAM/flash ni experimentos en el mando.

**Resultado:** los límites consultados por `0x20003B30` proceden de cuatro
campos RAM que una función real del cargador firmado inicializa con constantes.
El análisis se reprodujo sobre el **binario original** de 100.672 bytes,
SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.

## Cadena de punteros verificada

```text
global RAM 0x202081F4
   +0x0C → tabla 0x20016074
               +0x10 → contexto RAM 0x20212CD0
                         +0x70 → límite A
                         +0x74 → límite B
                         +0x78 → límite C
                         +0x7C → límite D
```

La rutina `0x20003B30` carga ese contexto y lee los cuatro campos.
La copia inicial `0x200164D8 → 0x20208000` abarca `0x830` bytes,
hasta `0x20208830`: **el contexto `0x20212CD0` queda fuera** de esa
copia. No se podía conocer su contenido solo leyendo la tabla inicial.

## Función que configura los valores

Se identificó **`0x20009904`**, referenciada en la tabla de proveedor
por el puntero Thumb `0x20009905` en `0x20016078`.

| Campo del contexto | Instrucción `STR` | Valor firmado que carga |
|---|---|---|
| `+0x70` | `0x2000992C` | `0x20002000` |
| `+0x74` | `0x20009934` | `0x20016D08` |
| `+0x78` | `0x2000993A` | `0x20208000` |
| `+0x7C` | `0x20009946` | `0x20216FFF` |

Los cuatro valores se han verificado como literales de la imagen en
`0x200099A0`, `0x200099A4`, `0x200099A8` y `0x200099AC`.
Los `LDR` que los recuperan y los `STR` que los escriben tienen
direcciones fijas contrastadas con Capstone.

Esto demuestra lo que **hace esa función si se invoca**. No demuestra
que se haya ejecutado en una sesión concreta del mando, ni excluye
posteriores escrituras sobre esos mismos campos.

## Consecuencias sobre la hipótesis de desbordamiento

La operación normal de cuatro bytes sobre los campos
`0x200159E0` y `0x200159EC` intersecta el primer intervalo
`0x20002000..0x20016D08` y es rechazada por el modelo del guard.

La hipótesis anterior utiliza un extremo de rango calculado
`(inicio + longitud - 1) mod 2³²` que puede ser inferior al inicio.
Cuando se introducen los cuatro límites de la función inicializadora
en las comparaciones exactas observadas de `0x20003B30`, el modelo
encuentra casos que **no son rechazados por esta función**. También
superan las dos comprobaciones previas de rango estudiadas en la PR #28.

**Esto no demuestra un acceso de escritura:** la operación requeriría
una longitud cercana a 3,5 GiB, mientras que el intervalo de RAM
declarado `0x20000000..0x2001FFFF` deja unos 42 KiB desde los
campos analizados. El backend `0x20002698` realiza escrituras
iterativas. No se ha verificado que pueda terminar, retornar al
despachador o dejar código y datos intactos. El comportamiento
real ante límites y fallos de bus no ha sido emulado exhaustivamente.

## Inventario de escrituras y límites de evidencia

La búsqueda lineal de instrucciones con desplazamientos
`#0x70/#0x74/#0x78/#0x7C` identifica los cuatro `STR` de la
función `0x20009904` y tres sitios candidatos adicionales en
otras funciones. **No son setters confirmados del mismo contexto**:
sus registros base no se han asociado con `0x20212CD0`, y un
barrido lineal no prueba exhaustividad ni alcanzabilidad.

| Cuestión | Resultado |
|---|---|
| Origen de los cuatro campos | **Trazado** |
| Valores de la función inicializadora | **Verificados sobre imagen original** |
| Resultado del guard con esos valores | **Reproducido offline** |
| Estado RAM medido en el mando | **No** |
| Modificación posterior de campos | **No descartada** |
| Escritura efectiva con la hipótesis de overflow | **No demostrada** |
| Ejecución de firmware propio / bypass HAB | **No demostrado** |
| Recuperación segura después del ensayo | **No verificada** |

## Reproducción

```sh
python -m unittest tests.test_fillmemory_dynamic_guard tests.test_fillmemory_init_limits -v
python -m tools.audit_fillmemory_dynamic_guard local/restricted_ivt_flashloader.bin --summary
python -m tools.audit_fillmemory_init_limits local/restricted_ivt_flashloader.bin
```

El workflow de GitHub descarga temporalmente una copia pública del
binario firmado, **verifica su SHA-256**, ejecuta los auditores y
elimina la copia. No publica firmware ni se comunica con el mando.

[Verificación del binario original en CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40236085352)

## Decisión de ingeniería

El hallazgo acota un posible problema de aritmética, pero
**no constituye un método de desbloqueo práctico demostrado**.
La tarea siguiente con sentido es verificar por separado la llamada de
inicialización en el flujo de arranque y, si se estudian efectos de
memoria, usar un **emulador limitado sin escrituras reales** que identifique
el primer punto de fallo. No se deben enviar operaciones con longitudes
enormes al mando único disponible.
