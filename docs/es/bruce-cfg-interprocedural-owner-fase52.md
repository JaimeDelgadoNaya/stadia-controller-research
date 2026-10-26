# Fase 52 — CFG interprocedural acotado: del propietario USB al singleton compartido

**26/10/2026 · PR #54 · Solo firmware OEM Bruce original firmado, SHA-256 fijado.**

## Resultado principal: escritura de configuración trazada a través de tres funciones

El nuevo auditor construye un **modelo simbólico limitado** sobre instrucciones originales ARM Thumb y sigue condicionalmente la dirección del propietario USB **\`0x2000A2A8\`** a través de tres funciones. Por primera vez hemos verificado **la transferencia concreta de dirección hasta la escritura global**, no simplemente la existencia de llamadas o de literales.

La prueba se ejecuta sobre la imagen OEM original firmada y rastrea:

1. \`0x60060FE8\` — cambio de modo; suponiendo que se solicita **modo 2**, llega por una ruta condicionada a \`0x6006102E: BL 0x60060F84\`.
2. \`0x60060F84\` — recibe \`owner\` en R0 y crea **R1 = owner+4** mediante \`0x60060F8A: ADDS R1,R0,#4\`. Llama a \`0x600550E4\` desde \`0x60060F90\`.
3. \`0x600550E4\` — conserva \`R1\` en R4 (\`0x600550EA\`), carga el singleton USB firmado **\`0x20004080\`** desde un literal relativo a PC y lo conserva en R5. Ejecuta \`0x6005512E: STR R4,[R5,#4]\`.

**Resultado abstracto de la escritura** en un camino que satisface las condiciones de entrada:

\`\`\`text
[0x20004084] = 0x2000A2AC
                │
                └── dirección de (owner + 4)
\`\`\`

La dirección **\`0x2000A2AC\`** es la *dirección* de la configuración, no el valor del puntero de clases almacenado en \`[0x2000A2AC]\`.

### Nueva condición de registro del método

Durante la construcción, el código firmado comprueba:

\`\`\`asm
0x600550F6  LDR R3,[R1,#4]  ; lee [owner+8] con R1=owner+4
0x600550F8  CMP R3,#0
0x600550FA  BEQ 0x600551A2 ; abortar si es nulo
\`\`\`

Por tanto, la ruta hacia \`0x6005512E\` también está **condicionada a que exista un método de configuración no nulo en \`owner+8 = 0x2000A2B0\`**, además de los demás guardas de estado del constructor.

Este control no revela **quién escribió previamente el método, cuál es su valor ni si el host puede influir en él**. La actualización firmada no es una instantánea de RAM.

## Control comparativo: modo 1

El auditor ejecuta la misma transferencia simbólica con semilla de modo 1 y modo 2:

| Caso de partida | Resultados de la búsqueda acotada |
|---|---|
| Modo 2 hipotético | 113 estados abstractos explorados. Se verifica el camino condicional hacia \`0x6005512E\` que transporta \`0x2000A2AC\`. |
| Modo 1 hipotético | 31 estados abstractos explorados. **No** aparece esa escritura del singleton de configuración por las tres funciones analizadas. |

Este contraste demuestra una **diferencia estática entre rutas**; no indica cuál seleccionó el mando al conectarlo.

## Qué cambió en el método de análisis

La fase 51 estudiaba principalmente instrucciones aisladas y transferencias de un salto. En esta fase, el auditor de propósito restringido:

- Modela registros con valores exactos de direcciones RAM/flash conocidas y aritmética básica de desplazamientos.
- Calcula correctamente el destino de las cargas \`LDR Rx,[PC,#imm]\` conforme a Thumb: \`((PC+4) & ~3) + imm\`.
- Sigue de forma **interprocedural** las llamadas firmadas al constructor de propietario y al instalador compartido, preservando registros callee-saved y descartando valores caller-saved tras funciones externas no modeladas.
- Recorre ambas ramas cuando desconoce el resultado de una condición, conservando la etiqueta **código condicional, no ejecución física**.
- Registra las lecturas de campos RAM sin inventar sus contenidos y detiene caminos que salen del CFG acotado.
- Impone límite de estados y anclas de instrucciones originales. Las pruebas sintéticas verifican el control de modo, los alias, el direccionamiento PC-relative y las invalidaciones de registros.

**Error detectado durante el desarrollo:** la primera auditoría sobre OEM falló porque el intérprete no calculaba la dirección base de PC en una carga literal. La comprobación falló de forma segura, se corrigió el cálculo y se introdujo una regresión específica que obliga a resolver el singleton real. Después, el auditor comprobó sobre el firmware firmado la cadena esperada. Este proceso ilustra por qué no basta con superar pruebas sintéticas.

## Lo que no permite concluir esta fase

**Todavía no se conocen los valores vivos** de:

| Dirección RAM | Dato pendiente |
|---|---|
| \`0x2000A2AC\` | Puntero al array de registros de clases activas |
| \`0x2000A2B0\` | Dirección del método dinámico de configuración |
| \`0x2000A2B4\` | Byte de cantidad de registros de clase |

El firmware OEM incluye una definición firmada de clase 10 y un distribuidor que puede seleccionarla, pero **no está demostrado que exista un registro clase 10 en la configuración USB realmente activada**. Tampoco se ha establecido una escritura arbitraria controlada por el ordenador, una entrada para código propio, ni un modo de superar **HAB CLOSED**. No se ha conectado el mando ni efectuado lecturas o escrituras sobre su RAM/flash/eFuses.

**El modelo no es un CFG de todo el firmware**: cubre las tres funciones indicadas y sus caminos a nivel de instrucciones. No contiene un análisis exhaustivo de todas las funciones que pudieran preparar \`owner+4/+8/+12\`.

## Siguiente experimento recomendado — fase 53

El mejor rendimiento de la próxima fase sería **buscar los inicializadores reales del método en \`owner+8\` y del array de clases en \`owner+4\`** mediante rastreo de escritores con control de alias y contexto de llamada, o bien pasar a evidencias físicas **pasivas, reversibles y de solo lectura** de la enumeración USB. Una captura de descriptores no prueba por sí sola la disposición de los punteros internos, por lo que debe marcarse como evidencia indirecta.

Antes de introducir cualquier firmware no OEM seguiría haciendo falta demostrar una ruta segura de ejecución y recuperación.

## Reproducibilidad

\`\`\`bash
python -m unittest tests.test_bruce_owner_cfg_phase52 -v
python -m tools.audit_bruce_owner_cfg_phase52 bruce_pvt_a_prod_signed.bin --out phase52-owner-cfg.json
\`\`\`

**Archivo de entrada obligatorio**: actualización OEM firmada original con SHA-256 \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[PR #54](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/54).
