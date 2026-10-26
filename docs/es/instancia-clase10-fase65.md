# Fase 65 — Guardas de instancia de clase 10 y enlace desde el owner

**26 de octubre de 2026.** Emulación acotada del Bruce OEM con SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa los [registros originales de fase 64](registros-clase-originales-fase64.md).

## Resultado principal

El código original consigue enlazar la primera entrada del array OEM con la instancia **`0x200040E0`**, partiendo del owner construido en fase 64, **si se simula éxito del driver USB de bajo nivel**. Ya no se impone `[singleton+4]=owner+4` para alcanzar el selector: esta escritura la ejecuta el código original en `0x6005512E`.

Esto es una demostración condicional virtual. El driver `0x6005556C` no se ejecuta: devuelve un estado inyectado. No se ha inicializado hardware real, medido la SRAM instalada ni ejecutado el callback `0x600613FD`.

## Guardas originales del inicializador

El método de clase 10 `0x60055320` usa la estructura `0x200040E0`. Si su primera palabra ya es distinta de cero, devuelve **2** antes de consultar el motor.

Con la estructura libre, llama al helper original `0x60055024`. Este comprueba la primera palabra del singleton USB **`0x20004080`** y el modo de su byte **`+0x0E`**. Si falta motor o el modo difiere de R0, devuelve **4**. Si ambas condiciones son válidas, copia el puntero del motor a la primera palabra de la estructura de clase y devuelve cero.

Los cinco experimentos ejecutan ambos métodos originales y solo interceptan sus helpers de guardado/restauración de estado:

| Motor virtual | Modo del motor | Clase ya ocupada | Resultado original, solicitando modo 2 | Instancia publicada en el registro |
|---|---:|---|---:|---|
| Ausente | 2 | No | 4 | No |
| Presente | 3 | No | 4 | No |
| Presente | 2 | No | **0** | **`0x200040E0`** |
| Presente | 2 | Sí | 2 | No se escribe nueva instancia |
| Ausente | 2 | Sí | 2 | No se escribe nueva instancia |

Son vectores de prueba, no estados leídos del mando. El caso ocupado sin motor muestra el orden de las comprobaciones; no demuestra que sea un estado físico alcanzable.

## Ruta original desde el owner

Se reutiliza en memoria el snapshot con los cuatro registros originales construido en fase 64. Antes de esta prueba se borran los estados virtuales del singleton, clase y motor, incluido el enlace que la etapa de selector de fase 64 inyectaba. Se conserva el owner original y se empieza en **`0x60060F84`** con R0=`0x2000A2A8`.

La ejecución original prepara R1=`owner+4`, R2=`owner+0x98` y obtiene el modo del byte `owner+0x10` (2 en el snapshot). A continuación atraviesa `0x600550E4`, el constructor del motor `0x60055350`, la búsqueda del primer selector y el método real de clase 10.

Con retorno simulado cero de `0x6005556C`, se observan estas escrituras originales:

| Campo | Dirección | Valor tras la inicialización de la primera clase |
|---|---|---|
| Singleton: motor | `0x20004080` | `0x200063C0` |
| Singleton: configuración | `0x20004084` | `0x2000A2AC` = `owner+4` |
| Clase10: motor | `0x200040E0` | `0x200063C0` |
| Clase10: registro original | `0x200040E4` | `0x2000A274` |
| Primera entrada: instancia | `0x2000A278` | **`0x200040E0`** |
| Clase10: bytes `+0x0C/+0x0E` | `0x200040EC/0x200040EE` | `0 / 255` |

La prueba se detiene en **`0x60055196`**, justo después de retornar del primer método de clase. No ejecuta las otras tres clases ni el registro final/retorno del owner. Por ello el retorno cero observado pertenece al método de clase, **no acredita éxito de todo el arranque USB**.

En el segundo experimento, el mismo driver devuelve **5** por stub. El código toma su rama de error y se detiene en `0x600553D0`, **antes de la limpieza** y sin llegar al inicializador de clase 10. Los punteros transitorios presentes en ese instante no describen el estado final después de cleanup.

## Límite previo: transición de modo

El snapshot intermedio de fase 64 tiene **`owner+0x90 = 0`**. La fase 53 ya acreditó que la transición al modo 2 exige un modo previo no nulo y distinto de 2. Esta prueba empieza directamente en `0x60060F84`: **no ejecuta ni satisface por sí sola las guardas de `0x60060FE8`**.

No se deduce que el arranque completo deje ese campo siempre a cero. El snapshot se tomó antes de finalizar toda la inicialización, y puede haber escritores posteriores. El estado real que permite la transición sigue pendiente de seguimiento.

## Suposiciones explícitas

- El snapshot hereda los modelos de subobjetos/mutex/copia de fase 64; no es un volcado físico.
- El driver `0x6005556C` es un stub que devuelve 0 o 5 y no realiza sus efectos sobre el hardware.
- `0x6013D3E0` se sustituye por la escritura de cero en el byte de estado de stack virtual, y `0x600D15E8` por una operación sin efectos. No se reproduce su implementación ni concurrencia real.
- Las instrucciones del owner, singleton, constructor del motor, selector, helper de acceso al motor e inicializador de clase 10 sí se ejecutan desde la imagen original.
- No se ejecutan callbacks de aplicación, las otras tres clases, cleanup de error, la transición de modo previa o el registro final del owner.

## Reproducción

```powershell
python -m tools.audit_class10_instance_phase65 local/bruce.bin --out local/phase65.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_class10_instance_phase65 -v
```

Requiere `requirements-emulation.txt` y el OEM exacto obtenido por separado del [archivo de firmware](https://github.com/StadiaMemories/firmware). El auditor exige SHA, instrucciones clave, punteros y resultados de los siete escenarios. Las pruebas negativas alteran una guarda, la escritura de instancia y el puntero del driver. **733 pruebas locales pasan**, incluidas las habilitadas contra el original. CI reproduce y compara la evidencia completa. La ampliación interna de la herramienta de fase 64 permite obtener su snapshot virtual sin publicarlo; su salida CLI anterior conserva el mismo contenido.

## Siguiente comprobación

Se ha eliminado la inyección del enlace al singleton en la ruta del owner, pero permanece una condición de hardware explícita: **el éxito real de `0x6005556C`**. La continuación debe seguir ese método y el estado previo a la transición de modo; después, conectar los eventos físicos con el callback OEM ya identificado.

No se demuestra activación física de clase 10, punteros elegidos por el host, ejecución propia, elusión HAB ni compatibilidad nativa con consolas. No se han enviado comandos al mando ni modificado firmware/eFuses.

[Evidencia](../../evidence/usb-class10-instance-phase65.json) · [Auditor](../../tools/audit_class10_instance_phase65.py)
