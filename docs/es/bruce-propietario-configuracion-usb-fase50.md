# Fase 50 — Objeto propietario USB: dirección RAM y condición de entrada en modo 2

**26 de octubre de 2026 · PR #52 · Investigación offline sobre la actualización OEM Bruce firmada.**

## Resultado central

Se ha localizado una **referencia de código original y firmada** al objeto propietario USB **\`owner = 0x2000A2A8\`**. La ruta OEM **\`0x60071404–0x60071430\`** pasa esa dirección a **\`0x60060FE8\`** y, para cierta entrada, coloca **R1 = 2**, el modo en el que la fase 49 demostró la invocación al constructor de configuración \`0x60060F84\`.

La segunda mitad del objetivo — **leer valores concretos de \`owner+4\`, \`owner+8\` y \`owner+12\` en el controlador real** — **no está demostrada**. Ninguno de los resultados permite decir que clase 10 está presente en la lista de clases activa.

## Cadena de código firmada verificada

En una función situada a partir de \`0x60071404\`, el firmware original realiza:

\`\`\`asm
0x60071408  MOV R4,R0
0x6007140A  BNE 0x60071420

; una rama diferente solicita modo 3
0x60071414  MOVS R1,#3

; rama compartida: apuntar al objeto USB propietario
0x60071416  LDR R0,[PC,#0x20]  ; literal a 0x60071438
0x6007141C  B.W 0x60060FE8

; si el argumento guardado R4 era igual a 1:
0x60071428  CMP R4,#1
0x6007142C  MOVEQ R1,#2
0x6007142E  MOVNE R1,#1
0x60071430  B 0x60071416
\`\`\`

El literal firmado en \`0x60071438\` es **\`0x2000A2A8\`**. Otro literal, en \`0x60071434\`, es \`0x2000A824\` y pertenece a una rama auxiliar distinta: **no hay que confundir esas dos direcciones**.

En \`0x60060FE8\` el código conserva R0 como R4 (\`0x60060FF0\`) y R1 como R5 (\`0x60060FF2\`), compara el modo con el estado anterior, realiza operaciones de cierre si hacen falta y evalúa:

\`\`\`asm
0x60061020  CMP R5,#2
0x6006102A  BNE 0x60061080
0x6006102C  MOV R0,R4
0x6006102E  BL 0x60060F84
\`\`\`

**Es una ruta condicional.** Que estas instrucciones estén en el firmware firmado no significa que se hayan ejecutado en un mando físico, ni que modo 2 esté activo ahora.

La función \`0x60060F84\` prepara la dirección **\`owner+4\`** como segundo argumento para \`0x600550E4\`; esta última función escribe **\`0x20004084 = owner+4\`** en el singleton compartido de la controladora USB, como se verificó en la fase 49.

## Direcciones que hemos acotado

Si la ruta anterior opera sobre el propietario **\`0x2000A2A8\`**, entonces:

| Campo del propietario | Dirección de campo en RAM | Interpretación del código original |
|---|---|---|
| \`owner+4\` | **\`0x2000A2AC\`** | \`config+0\`, puntero a array de registros runtime |
| \`owner+8\` | **\`0x2000A2B0\`** | \`config+4\`, método dinámico de la configuración |
| \`owner+12\` | **\`0x2000A2B4\`** | \`config+8\`, byte de recuento de registros |
| \`owner+0x10\` | \`0x2000A2B8\` | byte utilizado como modo de inicialización |
| \`owner+0x98\` | \`0x2000A340\` | destino para recibir puntero de instancia de motor USB |

Estas direcciones son **desplazamientos calculados**, no un volcado de memoria que muestre sus valores.

La dirección \`0x2000A2A8\` está **fuera de la región \`.data\` inicializada** \`0x20002740–0x20003FD8\` que se copia desde el firmware OEM al arrancar. Por tanto, no podemos obtener el contenido de ese objeto sustituyendo direcciones en la copia firmada de \`.data\`; podrían existir otras rutas de inicialización o escrituras durante la ejecución.

## Censo de referencias a la dirección

En los primeros \`0xFF000\` bytes firmados de la aplicación Bruce se han identificado **16 palabras de 32 bits alineadas** que contienen exactamente \`0x2000A2A8\`, en:

\`\`\`text
0x60041E98  0x6005AC14  0x6005ACC8  0x6005ACD4
0x6005ACEC  0x6005BC1C  0x600610F8  0x60064940
0x60065450  0x60071438  0x60074B00  0x60074E68
0x600755B8  0x600761CC  0x60079DD4  0x6007F714
\`\`\`

El mismo censo no encuentra **palabras literales directas alineadas** con valores \`0x2000A2AC\`, \`0x2000A2B0\` o \`0x2000A2B4\`. **Eso no descarta escritores:** es perfectamente normal que el código cargue solo la dirección base \`0x2000A2A8\` y escriba campos mediante \`STR [Rn,#offset]\`. Se han incluido ventanas de desensamblado cerca de los literales, pero las escrituras de esos tres campos **no se pueden atribuir exhaustivamente todavía**.

**Cuidado metodológico:** las ventanas que rodean un literal pueden atravesar datos que el desensamblador interpreta falsamente como instrucciones. Los catorce puntos cercanos no deben tratarse por sí mismos como rutas ejecutables. La auditoría diferencia anclas originales y simples candidatos lineales.

## Condición de decisión del proyecto

Lo que ya sabemos:

- El código firmado contiene un **registro de clase 10** y métodos que podrían atender un evento interno 1.
- En modo 2, la ruta descrita pasa un objeto RAM de configuración a la controladora USB.
- Se conoce una dirección concreta de ese objeto en **una ruta firmada**, lo que facilita inspecciones selectivas.

Lo que sigue **sin comprobarse**:

- Valor efectivo del puntero a array en \`0x2000A2AC\`.
- Valor efectivo del puntero de método en \`0x2000A2B0\`.
- Byte de recuento en \`0x2000A2B4\` y descriptores seleccionados.
- Si existe en el array activo un registro con selector **10**.
- Que el evento físico USB EP0 alcance ese registro o que el callback secundario esté realmente activo.
- Cualquier posibilidad de reemplazar punteros arbitrarios desde el host, ejecutar firmware propio, eludir **HAB CLOSED** o implementar compatibilidad Xbox/Switch 2.

La fase 50 constituye un **avance en procedencia y localización**, no una prueba de ejecución dinámica.

## Próximo experimento propuesto — Fase 51

Priorizar la identificación de las **instrucciones que inicializan \`owner+4/+8/+12\`** con una búsqueda de flujo de datos basada en la dirección base \`0x2000A2A8\`, incluyendo los inicializadores y llamadas que reciben ese puntero en registros. Si las escrituras dependen exclusivamente de estado en hardware, utilizar primero una **observación pasiva y no destructiva de descriptores/control USB**, sin escribir firmware ni cambiar eFuses. Los descriptores USB por sí solos tampoco muestran necesariamente las estructuras internas RAM; habría que distinguir evidencia indirecta de lectura directa.

## Auditoría reproducible

\`\`\`bash
python -m unittest tests.test_bruce_usb_owner_survey_phase50 tests.test_bruce_usb_owner_pointer_phase50 tests.test_bruce_owner_xrefs_phase50 -v
python -m tools.audit_bruce_usb_owner_survey_phase50 original-bruce.bin --out phase50-survey.json
python -m tools.audit_bruce_usb_owner_pointer_phase50 original-bruce.bin --out phase50-owner.json
python -m tools.audit_bruce_owner_xrefs_phase50 original-bruce.bin --out phase50-xrefs.json
\`\`\`

SHA-256 **\`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`**. Fuente: **archivo OEM Bruce de actualización**, no lectura del chip instalado. Todo el análisis fue offline, sin USB físico, escritura de flash ni eFuses.

[PR #52](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/52).
