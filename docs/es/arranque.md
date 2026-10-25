# Cadena de arranque y validación de actualizaciones — fase 9

[English](../en/boot-chain.md)

Este análisis corresponde únicamente al bootloader **169429**, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`, cargado
en `0x60800000`. Los nombres de funciones son descripciones de investigación,
no símbolos originales recuperados. `tools/analyze_bootloader.py` genera las
instrucciones de los rangos documentados.

## El salto a la aplicación exige superar la validación

La rutina `0x60801EF0` selecciona una dirección de aplicación y llama al validador
`0x6080200C` desde `0x60801F00`. Un resultado no nulo en el byte bajo toma la ruta
de error y retorna. Solo después de un resultado satisfactorio carga el puntero
de pila y el reset handler, deshabilita interrupciones, cambia el puntero de
vectores y salta al reset handler en `0x60801F46`.

El validador comprueba la base del espacio de aplicación, los rangos de vectores
y los punteros de metadatos antes de llamar al envoltorio HAB `0x60801F5C`.
Se observó otra llamada directa al validador en `0x60802838`; falta reconstruir
todo el despacho que la rodea.

## El envoltorio HAB

`0x60801F5C` llama a `entry` mediante `0x00200304`, exige HAB Success (`0xF0`),
invoca `authenticate_image_no_dcd` por `0x0020032C` y llama a `exit` mediante
`0x00200308`. Compara la dirección de entrada devuelta con la esperada. NXP
define la estructura RVT en su [implementación de referencia](https://github.com/nxp-mcuxpresso/sbl/blob/master/component/secure/semifunc/hab_rvt.c).

Si el puntero IVT de los metadatos de aplicación es cero, existe otra ruta.
Cuando el IVT de arranque compartido contiene un CSF, llama a `report_status`
mediante `0x00200324` y exige éxito y configuración HAB Open (`0xF0`). La
configuración Closed medida no cumple esa condición. La rama para un IVT
compartido sin CSF no se ha ejercitado y no demuestra que se pueda modificar
esa estructura de arranque firmada.

## La actualización tiene un modo de comprobación estructural

La rutina `0x608020A8` recibe una bandera en `r1`:

| Lugar de llamada | Bandera observada | Interpretación respaldada por las instrucciones |
|---|---:|---|
| `0x60801E02` | 1 | Comprueba el bootloader actual con autenticación habilitada |
| `0x60801E28` | 0 | La prevalidación del candidato es estructural |
| `0x60801E84` | 1 | La validación posterior a las operaciones intermedias habilita autenticación |

En la segunda llamada, `r1` vale cero porque conserva el resultado satisfactorio
de la primera, mediante `UXTB r1, r0` y el salto por cero. En `0x60802154`, una
bandera cero retorna tras las comprobaciones estructurales; una bandera no nula
termina llamando al envoltorio HAB desde `0x60802168`. Por tanto, superar la
prevalidación no demuestra que ya se haya comprobado criptográficamente la
imagen. Falta reconstruir las llamadas indirectas intermedias y toda la máquina
de actualización y recuperación. No se ejecutó ninguna actualización en esta fase.

## Observación aritmética: no es una vulnerabilidad demostrada

La función de rangos `0x60801FE6` comprueba que `start` y el resultado de 32 bits
`end = start + size - 1` estén, por separado, dentro del intervalo permitido.
No exige explícitamente que la suma no desborde ni que `end >= start`.

Ejemplo reproducible sin conexión:

```text
lower = 0x60000000; upper = 0x60FFFFFF
start = 0x60000010; size = 0xFFFFFFF8
end calculado (uint32) = 0x60000007
modelo de la función observada: acepta
modelo de intervalo sin desbordamiento: rechaza
```

Se trazaron tres llamadas directas en `0x608020FA`, `0x6080211C` y `0x60802138`.
Las primeras usan longitud fija `0x10`; la tercera obtiene una longitud de los
metadatos boot-data. Esto justifica investigar ese flujo, pero no demuestra que
el ejemplo alcance una operación aprovechable. La ruta con autenticación sigue
llamando después a HAB. No se han demostrado elusión de firmas, escritura
arbitraria, ejecución de código ni impacto en el dispositivo.

`python tools/model_ranges.py` reproduce únicamente la aritmética.

## Qué aporta esta fase

Ahora disponemos del bootloader permanente extraído, con firmas comprobadas y
evidencia de su flujo de control. Ni la bandera de validación estructural, ni la
ruta de imagen sin firma, ni el nombre «dev» constituyen un desbloqueo demostrado.
El siguiente trabajo es reconstruir metadatos, callbacks de actualización y
selección de respaldo antes de proponer otro experimento con el mando.
