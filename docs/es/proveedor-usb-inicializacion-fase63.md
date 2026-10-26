# Fase 63 — Proveedor del descriptor, configuración interna y escritores iniciales de flags

**26 de octubre de 2026.** Análisis offline de Bruce OEM con SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [coincidencia exacta de fase 62](coincidencia-descriptores-oem-fase62.md).

## Hallazgo principal

Se ha enlazado el proveedor del descriptor de 80 bytes con el **objeto de configuración ya identificado en fases 49–55** y se han localizado dos escrituras originales que inicializan sus flags a cero. El resultado es una ruta estática firmada, comprobada por ejecución acotada de fragmentos originales con RAM sintética; **no es una lectura de RAM instalada ni una captura de una petición USB física**.

## Procedencia del inicializador

En `0x600748EE` se carga el literal de `0x60074904`, cuyo valor es **`0x200064C0`**. Se pasa como R0 al inicializador **`0x60073BF0`** mediante BL en `0x600748F2`; `0x60073BF4` lo conserva en R4. Esto permite expresar las escrituras relativas posteriores como direcciones SRAM concretas del flujo OEM.

El inicializador prepara un límite de copia `R6 = base+0x3DC0+0x24` y un origen de registros `SL = base+0x3D80+0x34`. El bucle `0x60073DF0..0x60073E06` invoca métodos indirectos de objetos y copia tripletas de 12 bytes. La diferencia de límites es 48 bytes, correspondiente a cuatro tripletas. **Los métodos productores y el contenido real de esas tripletas no se ejecutan ni identifican en esta fase.**

## Campos escritos por el código OEM

| Campo | Dirección | Valor establecido en el flujo original |
|---|---|---|
| Objeto de configuración `owner` | `0x2000A2A8` | Base identificada en fases anteriores |
| `owner+4` | `0x2000A2AC` | Array `0x2000A274` |
| `owner+8` | `0x2000A2B0` | Método Thumb `0x60060D55` |
| `owner+12` | `0x2000A2B4` | Contador byte **4** |
| Objeto proveedor de descriptor | `0x2000A2A4` | Puntero a tabla `0x60105B88` |
| `owner+0x8C`, también `base+0x3E74` | `0x2000A334` | Puntero al objeto proveedor `0x2000A2A4` |
| Primera entrada de tabla del proveedor | `0x60105B88` | Método Thumb **`0x600619BD`** |

El cálculo del puntero al proveedor utiliza la distancia del bucle, un desplazamiento, multiplicación por el literal `0x2AAAAAAB`, máscara y MLA. La emulación ejecuta esas instrucciones originales y verifica que el puntero final es `0x2000A2A4`; no sustituye el cálculo por un valor impuesto.

Las escrituras principales son `0x60073E4E` (tabla del proveedor), `0x60073EAC` (método del owner), `0x60073EB2` (array), `0x60073EB6` (contador) y `0x60073EF0` (puntero al proveedor). Demuestran productores concretos dentro de este flujo OEM. No demuestran que sean los últimos escritores del estado instalado.

**Cuatro registros internos no equivalen a cuatro interfaces USB.** La enumeración física de fase 61 sigue declarando dos interfaces; no se atribuyen selectores concretos a estas cuatro tripletas todavía.

## Invocador indirecto del descriptor

El método `0x60060D54` usa un distribuidor TBH por **evento interno**. La entrada **12** lleva a `0x60060DB2`. Para un argumento de salida no nulo:

1. Lee `[base+0x3E74]` para obtener el objeto proveedor.
2. Lee su tabla y la primera palabra de dicha tabla.
3. Invoca `BLX R3` en **`0x60060DC4`**.

Con los campos construidos por el fragmento original, el destino es **`0x600619BC`**, el selector de fase 62. La ejecución virtual atraviesa ese BLX y ejecuta el selector original; con H sintético igual a cero y los flags virtuales inicializados, devuelve `0x6011E45A`, longitud 80 y retorno cero.

**Evento interno 12 no es USB bRequest 12.** No se ha establecido la traducción de una petición física hasta este evento ni medido esta invocación en el mando.

## Escritores iniciales de A/B

El código `0x6007408C..0x6007409E` construye `R3=base+0x433C` y ejecuta:

| Instrucción | Destino | Valor si R5 conserva el cero del inicializador |
|---|---|---|
| `0x6007409A STRB R5,[R3,#8]` | A: `0x2000A804` | 0 |
| `0x6007409C STRB R5,[R3,#9]` | B: `0x2000A805` | 0 |

`0x60073EA4 MOVS R5,#0` se ejecuta en el fragmento de metadatos. La prueba de escritores es un **fragmento separado** que conserva ese R5 sintético; no ejecuta el código intermedio. No se afirma que los valores virtuales sean los valores actuales del mando, ni que no existan otros escritores por alias, operaciones anchas o inicialización de bloques.

## Alcance de la ejecución y reproducción

La prueba tiene tres etapas explícitas:

- Metadatos originales `0x60073E44..0x60073EF4`, partiendo de un estado sintético al salir del bucle de cuatro registros. Las 48 posiciones de registros se rellenan con cero como fixture y **no representan registros de clase OEM medidos**.
- Escritores originales `0x6007408C..0x600740A0`, con A/B previamente en `A5/5A`, comprobando sus dos escrituras a cero.
- Despacho original desde `0x60060D54`, evento interno 12 sintético, hasta el selector y su retorno.

Las funciones externas de clear/copy del primer fragmento son stubs sin efecto que conservan R0; no se presupone haber reproducido sus efectos en memoria. Lookup del singleton, comprobación H y logging del selector también están interceptados. Hay límites de instrucciones, verificación de las salidas, registro de escrituras originales relevantes y rechazo de ejecución fuera de los fragmentos esperados.

```powershell
python -m tools.audit_usb_provider_phase63 local/bruce.bin --out local/phase63.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_provider_phase63 -v
```

Requiere `requirements-emulation.txt`. El auditor exige el hash completo, instrucciones semánticas, literales y entrada de tabla de eventos. Las pruebas negativas alteran el puntero de método, un STRB y la entrada del evento 12, comprobando su rechazo. **724 pruebas locales superadas**, con las pruebas contra el archivo OEM habilitadas. El workflow dedicado reproduce y compara la evidencia de esta fase contra la imagen SHA-verificada. El binario original no se publica.

## Lo que queda abierto

La configuración y el proveedor ya no carecen de productores identificados en el inicializador. Sigue pendiente determinar qué cuatro objetos proporcionan las tripletas, su relación con los selectores internos y los cambios posteriores del owner. La clase interna 10 **no está demostrada como activa**. La igualdad del descriptor físico tampoco prueba que la RAM instalada coincida con todo este estado construido.

No se han enviado comandos al mando, modificado firmware, ejecutado código propio en el dispositivo, superado HAB CLOSED ni conseguido compatibilidad nativa con consolas. El siguiente paso es resolver los cuatro productores que invoca el bucle original en `0x60073DFC`, sin tratar los registros sintéticos de esta prueba como evidencia OEM.

[Evidencia](../../evidence/usb-provider-phase63.json) · [Auditor](../../tools/audit_usb_provider_phase63.py)
