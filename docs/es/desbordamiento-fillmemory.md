# FillMemory — desbordamiento de 32 bits, límites del backend y decisión de viabilidad

**25/10/2026.** Investigación de solo lectura sobre el **cargador RAM firmado original**
(`restricted_ivt_flashloader.bin`, 100.672 bytes, SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`).
Reproducción aislada mediante GitHub Actions; sin envíos USB, escritura de flash ni
alteraciones de eFuses o del firmware del dispositivo.

## Hallazgo comprobado

El comando FillMemory entra por el handler `0x20003380`, llama a
`0x20003C86` y aplica las siguientes barreras **en este orden**:

1. **Política por operación, `0x200039A8`.** Con operación 0 selecciona
   la lista de cinco intervalos descrita en
   [la fase anterior](seguimiento-fillmemory-cfg.md).
2. **Protección dinámica de regiones, `0x20003B30`.** Comprueba
   solapamientos con límites obtenidos de estructuras RAM de ejecución.
   Los valores de esta unidad **no se han medido** en el estado operativo
   del cargador.
3. **Selección de mapa de memoria, `0x200039F4`.** Busca una región
   que incluya la dirección inicial y cuyo final declarado contenga
   el extremo calculado. La tabla firmada inicial contiene la región
   RAM `0x20000000..0x2001FFFF`.
4. **Backend del tipo de memoria.** Las regiones de RAM y periféricos
   enlazan a los métodos `0x20003D06` y `0x20003942`, respectivamente,
   que acaban en una rutina compartida de llenado `0x20002698`.
   Esa rutina utiliza escrituras de 1, 4, 8, 12 o 16 bytes y un bucle
   sobre la longitud restante, sin que esta auditoría demuestre una
   finalización segura ante longitudes enormes.

### Qué significa el desbordamiento

El primer filtro construye el extremo con instrucciones
`SUBS R2,#1` y `ADD R2,R1`: aritmética **módulo 2³²**.
Compara por separado el **inicio** contra el mínimo y el **final
calculado** contra el máximo, sin una comprobación específica
`final ≥ inicio`. El selector de mapa también calcula el extremo
módulo 2³² y contiene una lógica análoga.

La herramienta `tools/audit_fillmemory_wrap_model.py`, con huellas
de instrucciones del binario original, demuestra que **existen
longitudes positivas con desbordamiento que superan ambos prechecks
estáticos aun con inicio en las direcciones estudiadas de la tabla
Execute/Call**. Los escenarios se reproducen matemáticamente **sin
emitir comandos**.

**Esto NO constituye autorización de escritura.** Falta resolver
la barrera dinámica `0x20003B30` y el efecto real del backend.
Tampoco hay un mecanismo de ejecución propio ni recuperación fiable
demostrados.

### Por qué no equivale a una vía práctica

En el mapa original, la región RAM del cargador acaba en
`0x2001FFFF`. Desde los campos examinados hay solo unas decenas de
KiB hasta el final de esa región, mientras que la longitud que activa
el caso límite es muchísimo mayor. El backend usa un **bucle de
llenado real**, no una única escritura de palabra. Para terminar
una operación de esa longitud tendría que escribir fuera de la región
declarada; no se ha demostrado cómo respondería exactamente el
hardware ni la posibilidad de recuperar control posteriormente.

| Afirmación | Estado |
|---|---|
| Los dos prechecks estáticos tienen casos de extremo envuelto | **Reproducido en modelo fijado al original** |
| El backend sigue la longitud completa y no el extremo envuelto | **Código observado** |
| La protección dinámica permite uno de esos casos | **Sin determinar** |
| Se alcanza una escritura efectiva de la tabla de comandos | **No demostrado** |
| Se puede regresar al despachador y ejecutar código propio | **No demostrado** |
| Arranque seguro HAB CLOSED superado | **No** |
| Recuperación fiable del mando tras una prueba de escritura | **No verificada** |

## Código y reproducción segura

```sh
python -m unittest tests.test_fillmemory_wrap_model -v
python -m tools.audit_fillmemory_overflow local/restricted_ivt_flashloader.bin --print-disassembly
python -m tools.audit_fillmemory_wrap_model local/restricted_ivt_flashloader.bin --out local/wrap-model.json
```

El original privado/públicamente archivado se comprueba por SHA-256
**antes** de cualquier inferencia. La ejecución
[de verificación original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40234757038)
pasó; el informe de código e intervalos se produce sin conexión al mando.

## Decisión

La hipótesis de un **desbordamiento en los prechecks** tiene evidencia
de código y un modelo reproducible. Sin evidencia de escritura efectiva
y continuación controlada, **no se debe describir como exploit ni
utilizar para probar cambios en el único mando**. La fase adicional
útil es obtener **valores auténticos de la protección dinámica** o
reconstruir su inicialización estática, seguida de una emulación
controlada del backend. Si tampoco ofrece una ruta segura y recuperable,
cerrar FillMemory como vía práctica y explorar alternativas sin
modificación persistente.
