# Fase 58 — La lectura de `owner+0x80` conduce a un registro global de función y contexto

**26/10/2026.** Evidencia del firmware Bruce OEM firmado original, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Auditoría local de instrucciones, sin dispositivos, solicitudes USB ni escrituras de memoria física.

## Resultado principal: el helper no registra directamente el puntero owner

La fase 57 estableció una ruta estática y condicional:

```text
objeto dinámico (~164 bytes) → global 0x2001EE30
    → 0x6007E794 → [objeto + 0x80] (= owner si la ruta se inicializó)
    → 0x600D54B8
```

Ahora hay un cambio importante: **`0x600D54B8` reordena R1/R2 a R0/R1 y descarta su R0 de entrada como argumento directo al siguiente destino**. No podemos identificar la operación como una configuración de USB solo porque antes hubiera una lectura del campo `+0x80`.

Las seis instrucciones firmadas originales del adaptador son:

```asm
0x600D54B8 SUB    SP, #8
0x600D54BA MOV    R3, SP
0x600D54BC STM.W  R3, {R1, R2}
0x600D54C0 LDM.W  R3, {R0, R1}
0x600D54C4 ADD    SP, #8
0x600D54C6 B.W    0x6006386C
```

El destino `0x6006386C` almacena el nuevo R0 y R1 en dos palabras adyacentes de una estructura global. Sus **10 instrucciones originales** fueron fijadas por la auditoría:

```asm
0x60063874 LDR   R3, [PC, #0x10] ; literal 0x60063888 = 0x2000F878
0x60063876 LDR   R2, [SP]
0x60063878 STR.W R2, [R3, #0x37C] ; 0x2000FBF4
0x6006387C LDR   R2, [SP, #4]
0x6006387E STR.W R2, [R3, #0x380] ; 0x2000FBF8
```

No se asume que la estructura en RAM exista actualmente con esos valores; se observa el comportamiento del código que **podría escribirlos si se ejecutara**.

## Los dos pares de valores posibles

| Rama original | `0x2000FBF4`: puntero de función aparente | `0x2000FBF8`: contexto |
|---|---|---|
| `0x6007E7FA` | `0x600CE233` | `0` |
| `0x6007E81E` | `0x0000A9C5` | R4, puntero del objeto dinámico |

Los literales se verificaron en la imagen original: el primero está en `0x6007E824` y el segundo en `0x6007E828`; **son datos, no instrucciones fiables aunque el desensamblado lineal los muestre como código**.

Los dos tienen bit Thumb establecido. Las primeras instrucciones de sus destinos también se comprobaron:

- **`0x600CE232` (XIP)**: `BX LR`, retorno inmediato sin trabajo propio.
- **`0x0000A9C4` (ITCM copiada en el arranque)**: `B.W 0xB980`, salto hacia una rutina ITCM adicional.

Este patrón es **compatible con el registro/reemplazo de una pareja callback/contexto**, de modo que un camino instale un manejador sin efecto y el otro un manejador real unido al objeto. **La interpretación funcional requiere encontrar qué código lee e invoca las palabras `0x2000FBF4` y `0x2000FBF8`.**

## Resultado negativo importante

La lectura `[objeto+0x80]` que precede a `0x600D54B8` no se reenvía como R0 hasta `0x6006386C`; este backend recibe los valores que venían por R1 y R2. En la segunda ruta, el contexto R4 conserva una relación indirecta con owner (a través del objeto). **Eso no demuestra que el host USB pueda controlar ese registro ni ejecutar la función.**

En el firmware firmado solo se detectaron dos instrucciones directas `BL` a `0x600D54B8` en el barrido de formas de instrucción realizado: `0x6007E7FA` y `0x6007E81E`. Es un censo de candidatos, no un CFG exhaustivo que descarte otros tipos de llamada.

## Estado y siguiente objetivo

**Confirmado estáticamente:** adaptador de argumentos, literal global `0x2000F878`, escrituras a `0x2000FBF4/0x2000FBF8` y dos destinos Thumb firmados, uno de retorno inmediato y otro ITCM.

**Sin comprobar:** valores vivos de RAM, ejecución de los dos caminos, consumidor/invocador del par, conexión con EP0 o clase 10 activa, escritores de `owner+4/+8/+12`, ejecución no firmada y bypass HAB CLOSED.

**Fase 59 recomendada:** identificar los **lectores e invocaciones indirectas** del par global `0x2000FBF4/0x2000FBF8`; examinar además `0xB980` como manejador de la variante ITCM. Si no se demuestra una ruta desde peticiones USB reales, detener esta hipótesis como vía de control del host.

## Reproducción

```bash
python -m unittest tests.test_bruce_field80_helper_phase58 -v
python -m tools.audit_bruce_field80_helper_phase58 local/bruce_pvt_a_prod_signed.bin --out local/phase58-helper.json
```

[Auditoría OEM en GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40364601068) · [Evidencia estructurada](../../evidence/bruce-field80-helper-phase58.json). Sin USB físico, dump de RAM, escrituras flash ni eFuses.
