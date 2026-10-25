# Fase 17 — Registro de endpoints USB del fabricante

**Muestra analizada:** bootloader A del Stadia, build 169429, 131.072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Investigación **offline** sobre la imagen privada, sin conectar ni programar el mando.

## Resultado comprobado

La interfaz de fabricante documentada en la fase 14 tiene Bulk IN **`0x87`** y
Bulk OUT **`0x07`**, ambos con máximo de 512 bytes por paquete USB.

La rutina `0x60809EB8` construye sucesivamente **dos registros de endpoint**.
El puntero a la tabla de callbacks, `0x60814F24`, se carga en `0x60809F12`
y después se pasa, junto con el descriptor de endpoint, a `0x60806660`:

| Dirección | Instrucción o elemento confirmado |
|---|---|
| `0x60809F9C` | Literal que apunta a `0x60814F24` |
| `0x60814F24` | Puntero Thumb a `0x60809E30` |
| `0x60814F28` | Puntero Thumb a `0x6080A06A` |
| `0x60809F12` | `LDR.W R3,[R9,R6,LSL #2]`: callback según iteración |
| `0x60809F16` | Guarda puntero y contexto para el registro |
| `0x60809F1A` | Llama a `0x60806660` |
| `0x60809F7E` | Cambia a la segunda iteración |
| `0x6080A044` | Evento 9 llama a inicialización; evento 1, a retirada |

La rutina `0x60806660` identifica el endpoint mediante el byte
`[R1+2]`, extrae número (`& 0x0F`) y bit de dirección (`>>7`),
y **rechaza números mayores de 7**. Calcula el índice de registro:

```text
indice = 2 * (bEndpointAddress & 0x0F) + (bEndpointAddress >> 7)
registro = dispositivo + 12 * indice
callback = [registro + 0x0C]
contexto = [registro + 0x10]
```

La expresión de dirección presupone las direcciones USB normales con bits
reservados a cero. Los ejemplos derivados de la propia tabla USB son:

| Endpoint | Índice de registro | Desplazamiento del callback |
|---|---:|---:|
| Bulk OUT `0x07` | 14 | `0xB4` |
| Bulk IN `0x87` | 15 | `0xC0` |

Son **dos entradas distintas** de la estructura interna del USB stack.

## Qué hacen los dos callbacks registrados

- `0x60809E30`: función adaptadora que carga un puntero y un dato de la
  estructura de finalización, invoca `BLX R3` y devuelve cero.
- `0x6080A06A`: adaptador que delega en `0x6080A062`, el cual carga una
  función de otra estructura y efectúa `BX R3`.

**Limitación crítica:** el constructor toma descriptores de endpoint desde
una estructura en **RAM próxima a `0x200000D8`**. La tabla está ordenada
por iteración, pero todavía no se ha demostrado qué configuración de RAM
asocia cada adaptador con el endpoint **OUT `0x07`**. No sería correcto
atribuir al OUT uno de los adaptadores solo por el orden de la tabla.

Tampoco está reconstruido el destino final de esas llamadas indirectas,
el parser de comandos del host ni una conexión con las funciones de escritura
flash o autenticación HAB.

## Código reproducible

`tools/audit_vendor_endpoints.py` exige el SHA-256 **completo** y las huellas
SHA-256 de siete regiones de código, comprueba las instrucciones críticas y
el par de callbacks. El programa solo abre un archivo **local** y produce
un JSON saneado: sin USB, firmware modificado ni comandos físicos.

```powershell
py tools/audit_vendor_endpoints.py local/bootloader-a.bin --out local/fase17.json
py -m unittest discover -s tests -v
```

Las pruebas automáticas trabajan con memoria e instrucciones sintéticas;
el archivo binario original **no se publica**.

## Fase 18 propuesta

1. Reconstruir los valores iniciales de los descriptores RAM usados por el
   registrador `0x60806660`, con direcciones y evidencia de código.
2. Asignar de forma **verificable** el callback específico de Bulk OUT `0x07`.
3. Seguir su destino indirecto hasta la recepción del mensaje y las comprobaciones
   de autenticación/almacenamiento, si existe esa conexión.
4. Mantener cualquier experimento físico condicionado a una ruta demostrada y
   recuperable. **HAB CLOSED continúa sin elusión demostrada**.

No se ha ejecutado firmware personalizado ni se ha alterado el mando.
