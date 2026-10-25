# Revisión de la PR #24 — ¿FillMemory puede abrir una ruta de ejecución?

**Estado (25/10/2026): hipótesis aún no demostrada.** Este anexo responde a la
propuesta de examinar `FillMemory` por separado de `WriteMemory`.
Toda la revisión usa código público y comprobaciones **offline**; no se enviaron
comandos ni se modificó la electrónica.

## Lo verificado en la última PR

En el flashloader RAM firmado `restricted_ivt_flashloader.bin` de
100.672 bytes (SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`)
la tabla de comandos usada por el despachador apunta a:

| Orden | Tag | Handler Thumb | Habilitado |
|---|---|---|---|
| `WriteMemory` | `0x04` | `0x200030D9` | Sí |
| **`FillMemory`** | **`0x05`** | **`0x20003381`** | **Sí** |
| `Execute` | `0x09` | `0x200033A1` | No |
| `Call` | `0x0A` | `0x2000340D` | No |

La revisión anterior acreditó que la **fase de datos** de `WriteMemory`
pasa por un control de rangos `0x200039A8` al invocar su backend.
El tamaño del fragmento recibido por USB queda acotado al campo
de longitud uint16. Eso no demuestra nada por sí solo sobre
el tamaño total ni la validación de `FillMemory`.

## Por qué FillMemory merece una revisión separada

La interfaz pública independiente
[stadiatool/flashloader.py](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/flashloader.py)
incluye `fill_memory(address, size, pattern)` y utiliza el mismo
comando en `set32()` para expresar una actualización de un valor de
32 bits. `FillMemory` lleva **dirección, longitud y patrón de 32 bits**
en el comando, y **no tiene fase de transferencia de datos**.

El [manual oficial NXP](https://mcuxpresso.nxp.com/mcuxsdk/25.09.00/html/middleware/mcu_bootloader/docs/MCU_Bootloader_Reference_Manual/topics/mcu_bootloader_command_api.html)
explica que, **en la implementación general NXP**, `FillMemory`
sigue las **mismas reglas que `WriteMemory`**. Para memoria de palabras,
el inicio se alinea a cuatro bytes y la longitud se expresa en
múltiplos de cuatro; el manejo de flash exige precauciones adicionales.

**El flashloader de Google está restringido y no podemos asumir que el
manual genérico describe exactamente su código.** La comparación de
validación debe hacerse contra el manejador `0x20003380`.

## Cuatro comprobaciones decisivas para esta hipótesis

1. **Origen de parámetros.** Verificar de qué campos del paquete obtiene
   dirección, `byteCount` y patrón, y qué comprobaciones de cantidad,
   alineación o desbordamiento aplica antes de cualquier efecto.
2. **Backend.** Seguir llamadas directas y saltos indirectos del
   manejador `0x20003380`, identificando si convergen en la política
   de rangos utilizada por `WriteMemory` o en una validación distinta.
3. **Acceso efectivo a RAM.** Separar un comando reconocido de una
   operación aceptada sobre memoria realmente escribible. Un estado de
   respuesta «éxito» en documentación general **no** prueba acceso a
   estructuras de control protegidas en Stadia.
4. **Ejecución y recuperación.** Aunque existiera una vía para alterar
   temporalmente RAM, seguirían faltando una cadena segura de ejecución
   de código propio y la capacidad de recuperar el mando. HAB CLOSED
   continúa siendo una barrera independiente para arrancar imágenes
   alteradas tras reiniciar.

| Afirmación | Estado |
|---|---|
| `FillMemory` está habilitado en la tabla del cargador original | **Verificado en PR #24** |
| Dispone de argumentos dirección, longitud y patrón; sin fase de datos | **Verificado en implementación pública** |
| NXP indica que comparte reglas generales con `WriteMemory` | **Documentado por NXP** |
| El binario restringido de Google aplica exactamente la misma política | **No demostrado** |
| Puede alterar los campos de habilitación de `Execute/Call` | **No demostrado** |
| Se consigue ejecutar firmware propio o superar HAB CLOSED | **No demostrado** |

## Auditor offline añadido a la PR #24

`tools/audit_fillmemory_route.py` exige el SHA-256 original y confirma la
tabla de comandos. **Sin conexión con USB**, decodifica linealmente
`0x20003380..0x2000339F` con Capstone e inspecciona de forma acotada
las referencias directas de sus llamadas. Registra si aparecen las
funciones previamente asociadas al backend y política de
`WriteMemory`.

Esta inspección es **diagnóstica, no un análisis completo de flujo**:
una vista lineal puede atravesar datos literales, confundir rutas
condicionales u omitir llamadas indirectas o más profundas.
**La presencia de una llamada a la política no demuestra que se
ejecute para todos los casos; su ausencia en las vistas acotadas
tampoco demuestra un bypass.**

```sh
python tools/audit_fillmemory_route.py local/restricted_ivt_flashloader.bin --out local/fillmemory-review.json
python -m unittest tests.test_fillmemory_route -v
```

La ejecución sobre el binario original **aún no se ha completado en este
entorno** porque la copia binaria del cargador no está montada aquí.
Los tests de CI utilizan exclusivamente secuencias sintéticas;
no implican aceptación de ninguna operación sobre un mando real.

## Dictamen provisional

`FillMemory` es una **pista razonable para auditar**, al estar habilitado
y no depender de la fase de datos de `WriteMemory`. **No es una
ruta de ejecución validada.** No debe intentarse escribir regiones RAM
de control ni ejecutar operaciones sobre el mando antes de verificar
la implementación real y una recuperación segura.
