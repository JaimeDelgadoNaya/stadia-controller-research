# Bruce: registro de callbacks USB y límite de EP0 (PR #34)

**Fecha:** 26 de octubre de 2026. Investigación **solo lectura** sobre la aplicación Bruce OEM firmada: 1.050.984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Es un **archivo de actualización**, no una lectura de la flash instalada ni una comprobación de `SCB.VTOR` en vivo.

## Resultado principal

En la [fase #33](traza-ep0-bruce.md) se trazó de manera condicional:

```text
OTG1 IRQ 113 → 0x600610D0 → veneer 0x6013D1F8
→ IRQ USB ITCM 0x00001110 → ENDPTSETUPSTAT
→ BL 0x0000BA68 → XIP 0x600D0FB6
→ cálculo de slot endpoint → BLX R5 (0x600D104E)
```

La fase #34 **ha localizado exactamente la rutina que registra la pareja función/contexto** utilizada por esa llamada indirecta, así como sus dos llamadas directas en código XIP.

### Rutina de registro `0x600D10B8`

El código original examina un descriptor de endpoint desde el argumento `R1` y una pareja `función, contexto` desde `R2`. Estas son las instrucciones relevantes, verificadas contra la imagen completa y protegidas con pruebas de anclaje:

| Dirección | Instrucción / efecto |
|---|---|
| `0x600D10C0` | `LDRB R4,[R1,#2]`: dirección de endpoint del descriptor |
| `0x600D10C2` | `AND R5,R4,#0xF`: número de endpoint |
| `0x600D10C6` | `CMP R5,#7`: límite máximo |
| `0x600D10CA–0x600D10D0` | Combina número y bit IN/OUT en `2*número+dirección` |
| `0x600D10D6` | `MLA R3,R5,R3,R0`: objeto dispositivo + 12 × índice |
| `0x600D10DA` | `STR R2,[R3,#0x10]`: contexto del callback |
| `0x600D10DE` | `STR R4,[R3,#0xC]`: puntero a función |
| `0x600D10E0` | `STRB ...,[R3,#0x14]`: reinicia estado de entrada |
| `0x600D10E8` | Deriva al controlador `0x600D0EDE` con operación 2 |

El controlador utiliza **12 bytes por entrada**. Para los índices hipotéticos **EP0 OUT=0** y **EP0 IN=1**, los punteros estarían a `objeto+0x0C` y `objeto+0x18`, respectivamente; los contextos a `+0x10` y `+0x1C`. Estas direcciones son **relativas al objeto**, cuya identidad y contenido runtime no han sido verificados.

El código `0x600D1122` borra la pareja función/contexto de la entrada seleccionada bajo condiciones de desregistro.

### Rutas de instalación por descriptor

Hay dos llamadas directas `BL` al registrador encontradas por el censo de código XIP original:

- **`0x60054782`**: en `0x60054728`, recorre los descriptores de endpoints, prepara `R1` con una estructura local y `R2` con la pareja función/contexto.
- **`0x60054850`**: en `0x600547AC`, recorre otro conjunto de descriptores bajo guardas de configuración.

También se han identificado sus llamadores inmediatos: `0x600CFD92` → `0x60054728`; `0x600D03AC` → `0x600547AC`, y el tail-call `0x600CFDA0` → `0x60054728`.

Estas rutas reflejan **registro dirigido por descriptores de endpoints**. No está demostrado que incluyan EP0: los endpoints de control suelen configurarse de modo distinto a los endpoints de datos descritos por interfaces.

### Constantes de función registrables

La resolución de literales Thumb de los bucles ha identificado:

| Literal XIP | Puntero Thumb | Código firmado |
|---|---|---|
| `0x600547A0` | `0x600CFC71` | `0x600CFC70` |
| `0x600547A4` | `0x600CFC35` | `0x600CFC34` |
| `0x600547A8` | `0x600CFC53` | `0x600CFC52` |
| `0x60054870` | `0x600CFC1B` | `0x600CFC1A` |

Las cuatro rutinas contienen una **redirección condicional hacia la función de otro objeto de clase** (cargan función desde `[contexto+4]` y `[objeto]`, terminando en `BX R3`). Preparan identificadores internos de evento `1,2,3,4` o limpian indicadores del contexto. Un `BX` a un puntero tomado de objetos de clase **no implica que el host USB pueda elegir arbitrariamente esa dirección**.

### Observaciones complementarias

- Censo lineal: **siete** regiones con patrón de stride de 12 bytes y escrituras cercanas; **una** coincide con el registrador comprobado. Las demás son candidatas no concluyentes.
- Datos copiados al arrancar: **258** palabras con forma de puntero Thumb bajo un criterio amplio, **56** en un rango XIP cercano a USB. **No** son 258 callbacks USB ni prueban los valores actuales de los slots.
- Búsqueda de literales de 32 bits alineados: **cero** referencias al puntero Thumb del registrador `0x600D10B9`, también cero para los bucles `0x60054729`/`0x600547AD`. Es un barrido acotado; no descarta llamadas calculadas, ni referencias sin alinear. Sí se conoce el literal del veneer a `0x600D0FB7` en el offset `0xC288`.
- Los valores `0x81`, `0x83`, `0x84` del host son campos `bRequest` del SETUP; **no** identificadores de los cuatro eventos de clase observados.

## Estado verificable del objetivo

| Pregunta | Respuesta |
|---|---|
| ¿Qué código instala punteros de endpoint? | **`0x600D10B8`, verificado estáticamente** |
| ¿Cómo selecciona el slot? | `2*(endpoint&0x0F)+bit7`, stride 12 |
| ¿Qué bucles lo llaman? | `0x60054728` y `0x600547AC` |
| ¿Qué funciones constantes proponen esos bucles? | Cuatro forwarders `0x600CFC1A/34/52/70` |
| ¿Cuál está registrada concretamente en EP0? | **No establecido** |
| ¿Dónde se interpreta el `bRequest` `0x81/0x83/0x84`? | **No establecido** |
| ¿Hay ejecución propia o HAB CLOSED bypass? | **No demostrado** |
| ¿Hay modo Xbox/Switch 2 directo? | **No** |

**Siguiente línea acotada:** identificar la inicialización del callback específico de control EP0 en el **objeto de clase** y sus funciones `bRequest`; comprobar valores procedentes del setup y sus efectos, sin extrapolar el callback de endpoints de datos. Si no aparece un receptor controlable y un procedimiento de recuperación independientemente verificado, no intentar flasheos.

## Reproducibilidad

```sh
python -m unittest tests.test_bruce_ep0_registration -v
python -m tools.audit_bruce_ep0_registration local/bruce_pvt_a_prod_signed.bin --out local/ep0-registration.json
```

El workflow `signed-app-host-boundary.yml` descarga temporalmente los originales públicos, verifica SHA-256, ejecuta auditores offline y elimina las muestras. No requiere acceso al mando. Las exploraciones heurísticas y las instrucciones ancladas están diferenciadas en el JSON para evitar afirmar cadenas de ejecución no probadas.
