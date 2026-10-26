# Fase 45 — Puente condicional entre bRequest USB y el despachador OEM de clase 10

**26/10/2026 · PR #47 · Ingeniería inversa exclusivamente offline del fichero de actualización Bruce original firmado.**

## Qué se ha reconstruido

Esta fase une los anclajes ya demostrados de fases 40–44 y confirma **la continuidad del registro R1**, que contiene un candidato a `bRequest`, desde el despachador de clase a los 13 casos firmados. No equivale a demostrar un paquete USB físico ni que clase 10 esté seleccionada en el dispositivo real.

1. El registro de clase OEM firmado en `0x60104BA4` contiene selector **10**, inicializador `0x60055321` y función de evento **`0x600D0E59`**.
2. El archivo OEM copia a RAM en `0x200030F4` un registro de clase 10 cuyo primer campo contiene el puntero Thumb **`0x600613FD`**.
3. En el forwarder firmado `0x600D0E58`, el bloque `0x600D0EA2..0x600D0EBE` comprueba `bmRequestType & 0x1F == 1` (receptor de tipo interfaz), compara el byte de `wIndex` en `buffer+4` con `objeto+0x0D` y ejecuta `0x600D0EB8: LDRB R1,[R1,#1]` para cargar el **byte de petición**. Con `0x600D0EBE: BX R3` despacha a la función obtenida del registro del objeto de clase.
4. Si ese registro en RAM referencia `0x600613FD`, el handler original comprueba `R1 > 0x7F`, y, si la pareja RAM de la fase 44 contiene el manejador firmado activo **`0x600DB029`** y contexto **`0x20003670`** (en vez del sentinela de arranque), realiza `0x60061416: BLX R3`. No cambia R1 antes de llamar.
5. `0x600DB028: B.W 0x60077360`; la función resta `0x80` a R1, compara con `0x0C` y usa la tabla de salto `TBB [PC,R1]` para seleccionar una de **13 rutas, 0x80–0x8C**.

**Conclusión verificada en código firmado:** si el forwarder está activo, selecciona el registro de clase 10 y el callback secundario ha sido sustituido por el OEM firmado, su byte `buffer[1]` determina el índice del despachador, previa validación de receptor e interfaz. No existe prueba de que un puerto USB real alcance ese forwarder ni de que las condiciones se cumplan en un mando.

## Matriz de condiciones para una simulación sintética

| Dato de entrada sintético | Resultado condicional |
|---|---|
| `bmRequestType = 0x20` o `0x22` | Receptor distinto de interfaz: descartado |
| `bmRequestType = 0x21` o `0xA1` | Satisface exclusivamente el guard `& 0x1F == 1`; otras comprobaciones externas no modeladas |
| `wIndex` bajo distinto de `objeto+0x0D` | Descartado por comprobación de interfaz |
| `bRequest = 0x7F` | Descartado por el guard del handler de clase 10 |
| `bRequest = 0x80`, `0x81`, `0x83`, `0x84`, `0x8C` | Selecciona las respectivas ramas originales, **solo si** el callback está instalado |
| `bRequest = 0x8D` o `0xFF` | Pasa `R1 > 0x7F`, pero no la cota `0x80–0x8C` del despachador |
| Callback RAM contiene `0x600D4F05` | El callback secundario no se invoca; valor predeterminado de inicialización |
| Callback RAM contiene `0x600DB029` | Se podría invocar el handler firmado si se cumplen las otras condiciones |

El modelo de prueba **nunca envía una solicitud real ni ejecuta un `BLX` sobre memoria suministrada por un host**.

## Inspección individual de los 13 casos

Se ha decodificado cada rama desde su **destino auténtico en la tabla Thumb TBB**, evitando tratar los 13 bytes de datos de salto como instrucciones. Se inspeccionan stores, branches y llamadas de cada fragmento, sin suponer un CFG global completo.

Las tres ramas priorizadas previamente contienen efectos locales precisos:

- **`0x81`**, entrada `0x60077392`: calcula `R4=R0+0x190`, escribe `R4` en `[R5+4]` y deriva al bloque compartido que registra el indicador `8` en `[R5+8]`.
- **`0x83`**, entrada `0x600773A4`: calcula `R0=R0+0x12C`, pone `0` en `[R2+8]` y deriva a una rutina común original firmada. La semántica posterior de esa rutina está fuera de este bloque.
- **`0x84`**, entrada `0x600773AE`: calcula `R4=R0+0x1D8`, escribe ese puntero en `[R2+4]` e indicador `2` en `[R5+8]`.
- **`0x8B`**, entrada `0x60077494`: llama a `0x60077744`, función original firmada, y sigue a salida común.
- **`0x8C`**, entrada `0x6007749A`: llama a `0x60077720`, almacena el resultado en `[R4+0x198]`, llama a `0x60077730`, almacena su resultado en `[R4+4]` y salta a `0x60077396`, reutilizando parte de la salida de `0x81`.

**No se observa en los fragmentos locales `0x81`, `0x83` y `0x84` una instrucción que cargue desde el byte de petición una dirección de código y la escriba directamente en `0x20009EF8`.** Esto no descarta rutas indirectas ni prueba que el conjunto de comandos sea seguro o no explotable.

Las rutas restantes `0x80`, `0x82`, `0x85–0x8A` se han censado con sus stores y llamadas: están detalladas en la salida reproducible de la herramienta, sin atribuirles aún una finalidad.

## Barrera que no se ha superado

El punto ausente es la **alcanzabilidad física completa USB1 EP0 → evento de clase 10**. Se conocen instrucciones que procesan campos con estructura de SETUP, pero no se ha demostrado el enlace vivo entre el IRQ/transferencia de control, la selección de clase, un objeto concreto y el callback secundario activo. Tampoco se dispone de un volcado de flash instalada ni de una lectura runtime de RAM.

No se ha logrado ejecución de código propio, elusión de HAB CLOSED, garantía de recuperación ni compatibilidad nativa Xbox o Switch 2. No se ha tocado el mando físico.

## Reproducción

```bash
python -m unittest tests.test_bruce_ep0_class10_bridge_phase45 tests.test_bruce_class10_case_effects_phase45 -v
python -m tools.audit_bruce_ep0_class10_bridge_phase45 local/bruce_pvt_a_prod_signed.bin --out local/phase45-bridge.json
python -m tools.audit_bruce_class10_case_effects_phase45 local/bruce_pvt_a_prod_signed.bin --out local/phase45-cases.json
```

Los auditores exigen exactamente la imagen OEM original de SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. En CI el archivo se descarga temporalmente, se verifica y se elimina.

**Siguiente paso recomendado — fase 46:** investigar el enlace desde el controlador USB/EP0 a `0x600D0E58`, y las ramas condicionales que instalan `0x600DB029`; utilizar emulación sintética de datos únicamente cuando las rutas estén delimitadas por instrucciones verificadas.

[PR #47](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/47).
