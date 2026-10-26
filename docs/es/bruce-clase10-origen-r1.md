# Fase #39 — procedencia real del puntero R1 del inicializador de clase USB 10

**26 de octubre de 2026.** Análisis **exclusivamente offline** sobre el archivo de actualización Bruce OEM original firmado: 1.050.984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No es lectura de la flash del mando real.

## Resultado

La [fase #38](seleccion-clase-bruce-fase38.md) demostró que el registro de clase `10` empieza en `0x60104BA4`, cuyo método `+0` es `0x60055320` y cuyo método `+8` es `0x600D0E58`. La pregunta pendiente era **qué valor trae R1 a `0x60055320`**.

El código original firmado permite reconstruir la selección condicionada de una **entrada de 12 bytes** de configuración de interfaces. La procedencia se verifica mediante **32 anclas de instrucciones Thumb** fijadas en `tools/audit_bruce_class10_r1_origin.py`.

| PC | Acción original verificada |
|---|---|
| `0x600550EA` | `MOV R4,R1`: conserva el argumento original `R1` de la función de configuración `0x600550E4` |
| `0x6005512E` | `STR R4,[R5,#4]`: guarda el puntero original en una estructura global, si se ejecuta la rama de inicialización |
| `0x60055178` | `LDR R3,[R5,#4]`: recupera el puntero conservado |
| `0x6005517A` | `LDR R1,[R3]`: carga el puntero a la base de entradas |
| `0x60055174` | `MUL R8,R3,R8` después de `MOVS R3,#12`: calcula el desplazamiento de interfaz |
| `0x60055180` | `ADD R1,R8`: fija `R1 = [argumento_original] + 12×índice` |
| `0x60055184` | `LDR R2,[R1,#8]`: obtiene descriptor de interfaz desde la entrada |
| `0x60055186` | `LDRB R2,[R2,#4]`: extrae el código de clase en el descriptor |
| `0x60055182/88` | obtiene el selector del registro en `+12` y compara ambos códigos |
| `0x6005518C–94` | carga el método `+0` del registro que coincide, prepara `R2=R1+4` y llama por `BLX R3` |
| `0x60055324` | inicializador clase 10: `MOV R6,R1` |
| `0x6005533A` | guarda `R6` en `[objeto_global_clase10+4]` en el camino correspondiente |
| `0x600D0EB6–BE` | en la rama de solicitudes de clase, obtiene `[objeto+4]`, lee su primera palabra y salta por `BX R3` |

**Conclusión:** en este camino de código firmado, el inicializador **no recibe un puntero creado directamente a partir de `bRequest`**. Recibe la dirección de una entrada de configuración de 12 bytes previamente proporcionada por otro componente de la aplicación.

### Estructura de entrada deducida

| Desplazamiento | Lectura/escritura observada | Interpretación |
|---|---|---|
| `+0` | la ruta posterior de clase hace `LDR R3,[puntero_entrada]` | **Posible puntero al callback**, pero no se ha identificado su escritor original |
| `+4` | el inicializador recibe `R2=entrada+4` y deja allí un puntero de objeto de clase | Puntero de salida hacia el objeto de clase |
| `+8` | se carga `[entrada+8]` y después `[descriptor+4]` | Puntero a descriptor de interfaz |

Las direcciones globales de RAM aparecen como literales firmados: `0x20004080` para el estado de configuración y `0x200040E0` para el objeto de clase 10. **Que la región esté documentada en el binario no demuestra su contenido durante una ejecución real**.

### Origen del primer puntero: todavía no demostrado

Un censo XIP de instrucciones `BL` directas encontró **cero** llamadas a la función de configuración `0x600550E4`, a su método clase 10 `0x60055320` y a dos funciones auxiliares estudiadas. Se conocen llamadas **indirectas** al inicializador mediante la tabla de clases. Este resultado negativo es limitado: una API llamada a través de tablas, registros o punteros calculados no genera necesariamente llamadas `BL` directas.

Un censo de palabras alineadas de la imagen original encontró:

- `0x600550E5`: **0** referencias literales de 32 bits.
- `0x60055321`: **1** referencia, en el registro estático de clase 10.
- `0x600D0E59`: **1** referencia, en el registro estático de clase 10.
- `0x200040E0`: **1** literal, usado por el inicializador.
- `0x20004080`: **5** literales, vinculados con rutinas de configuración.

**El origen de la primera palabra `[entrada+0]`, que podría ser el callback de clase final, sigue sin resolverse.** Tampoco se ha verificado que una instancia activa de EP0 utilice este objeto, o que las peticiones USB `0x81/0x83/0x84` alcancen la ruta.

## Distinción esencial

La secuencia estática conecta el mecanismo de **selección de clase 10** con la **conservación de un puntero a registro de configuración** y un posible acceso posterior a su primera palabra. Esta observación **no** equivale a ejecución arbitraria de código: los campos de `bRequest` se pasan como argumentos y nada demuestra que el host pueda rellenar esa primera palabra.

La emulación sintética de fases #37 y #38 tampoco ejecutó callbacks reales ni estableció un enlace físico completo hasta EP0. **No se ha demostrado bypass HAB CLOSED, firmware instalable, recuperación segura ni compatibilidad directa con Xbox/Switch 2**.

## Siguiente investigación delimitada

Localizar **quién construye las entradas de 12 bytes y escribe `[entrada+0]`**. Priorizar búsquedas de rutinas que asignan punteros de callback a registros de configuración de interfaces y los pasan a `0x600550E4` mediante un puntero de función. Si solo aparecen direcciones estáticas firmadas, será una señal negativa para una vía de ejecución personalizable desde USB.

## Reproducción

```sh
python -m unittest tests.test_bruce_class10_r1_origin -v
python -m tools.audit_bruce_class10_r1_origin local/bruce_pvt_a_prod_signed.bin --out local/class10-r1.json
```

GitHub Actions obtiene únicamente una copia pública temporal, verifica SHA y ejecuta el auditor en modo solo lectura. No envía USB ni flashea el dispositivo.

[PR #39](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/39).
