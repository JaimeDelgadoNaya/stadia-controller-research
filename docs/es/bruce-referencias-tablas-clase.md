# Bruce: auditoría de referencias a tablas de clase (fase #36)

**26 de octubre de 2026 · solo lectura.** Auditoría reproducible sobre el firmware original OEM Bruce **firmado** (archivo de actualización; 1.050.984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). Ninguna instrucción se ejecutó en el mando.

## Pregunta

La [fase #35](setup-control-clase-bruce.md) identificó un reenvío condicional de `bRequest` mediante el manejador `0x600D0E58` y un puntero Thumb `0x600D0E59` dentro de la tabla firmada de datos en `0x60104BAC`. **¿Hay una referencia de código demostrable que instale ese manejador en el objeto activo de EP0?**

La búsqueda previa de palabras de 32 bits no había encontrado un literal exacto `0x60104BA4`. En #36 se amplió a cargas Thumb PC-relativas de palabras de memoria y a parejas locales `MOVW/MOVT` para direcciones en `0x60104B80..0x60104BDF`.

## Hechos obtenidos del original firmado

| Prueba | Resultado verificado |
|---|---|
| Lecturas literales PC-relativas de palabras que apuntan dentro de `0x60104B80..0x60104BDF` | **Una coincidencia**, `0x6005679A: LDR R5,[PC,#0x5C]` |
| Literal leído por esa instrucción | `0x600567F8` contiene `0x60104BDC` |
| Pares de `MOVW/MOVT` consecutivos próximos que reconstruyen una dirección del rango | **Cero candidatos** en el barrido acotado |
| Referencia a `0x60104BA4` o al puntero de función `0x600D0E59` que demuestre una instalación de EP0 | **No hallada** |
| Callback activo en RAM, origen de las solicitudes `0x81/0x83/0x84` o ejecución de código propio | **No demostrado** |

### La coincidencia pertenece a otra tabla

Se comprobaron, **instrucción por instrucción**, los siguientes pasos del código OEM original:

```asm
0x6005679A    LDR     R5,[PC,#0x5C]       ; carga 0x60104BDC
0x600567A2    ADD.W   R2,R5,R3,LSL #3     ; índice * 8 bytes
0x600567A6    LDR     R2,[R2,#4]          ; puntero de función de esa entrada
0x600567AA    LDRB.W  R3,[R5,R3,LSL #3]   ; primer byte de la misma entrada
0x600567B6    BLX     R2                  ; llamada indirecta
```

El código **utiliza explícitamente un paso de ocho bytes**, a partir de `0x60104BDC`. Es una **tabla indexada diferenciada** del fragmento `0x60104BA4..0x60104BAC`; no puede contarse como prueba de que la función `0x600D0E58` se haya registrado para EP0.

La región `0x60104B88..0x60104BB7` contiene funciones Thumb contiguas, además de palabras numéricas `2, 4, 10`; estas secuencias son **compatibles** con varias estructuras de cuatro palabras, pero **no disponemos de tipos originales, símbolos ni referencia de código que confirme sus fronteras exactas**. Por tanto, la dirección `0x60104BA4` **no se puede llamar con seguridad «comienzo de tabla»**. Lo inequívoco es que `0x60104BAC` almacena `0x600D0E59`. En la fase anterior se diferenciaron `0x60104BA4` y `0x60104BC4` por sus referencias literales; la presente fase refina la interpretación estructural sin afirmar que una de ellas esté instalada en EP0.

## Qué demuestra y qué no

El auditor `tools/audit_bruce_class_table_xrefs.py` verifica primero **tamaño y SHA-256** y después busca referencias PC-relativas y parejas `MOVW/MOVT`; además, compara con anclas ARM firmadas la instrucción `BLX` y la multiplicación por ocho. `tests/test_bruce_class_table_xrefs.py` comprueba el cálculo de PC, rechazo de imagen falsa y detección de deriva semántica.

El barrido Thumb es **lineal**, puede interpretar palabras de datos como instrucciones y no es un análisis exhaustivo de flujo de control. No cubre referencias vía `ADR` sintetizado, sumas de bases, registros reubicados, carga del objeto en RAM, saltos indirectos de inicialización ni trazas de la clase activada. **Ausencia de referencia directa no demuestra que la tabla no se utilice.**

**Próximo paso:** estudiar el registro dinámico del objeto de interfaz que puede llamar a `0x600D0E58` y reconstruir el callback recibido en `[R0,#4]`; posteriormente vincular las solicitudes `0x81/0x83/0x84` a una ruta de consulta de solo lectura. Si no aparece un punto de ejecución verificable y un procedimiento de recuperación, **no escribir firmware en el controlador HAB CLOSED**.

No hay ejecución propia, bypass de firma, instalación funcional de firmware ni compatibilidad directa Xbox/Switch 2 demostrada.

## Reproducción

```sh
python -m unittest tests.test_bruce_class_table_xrefs -v
python -m tools.audit_bruce_class_table_xrefs local/bruce_pvt_a_prod_signed.bin
```

GitHub Actions descarga la imagen pública solo en un runner efímero, verifica SHA-256 y elimina los archivos. No hay comunicación USB con el hardware.
