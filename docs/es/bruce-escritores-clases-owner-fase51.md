# Fase 51 — Referencias ejecutables del propietario USB y búsqueda de escritores de clases

**26 de octubre de 2026 · PR #53 · Auditoría exclusivamente offline de la actualización OEM Bruce firmada.**

## Resultado de la fase

Se han distinguido **16 apariciones literales** de \`0x2000A2A8\` de **11 instrucciones candidatas que cargan realmente el literal mediante direccionamiento relativo a PC** dentro de la imagen OEM firmada. Se siguieron sus usos locales y las funciones OEM llamadas directamente por varios de los wrappers.

**Resultado de la búsqueda estricta: ningún escritor de \`owner+4\`, \`owner+8\` o \`owner+12\` ha podido demostrarse en esas secuencias locales.** No significa que las escrituras no existan. El análisis tiene un alcance acotado; no reconstruye exhaustivamente el flujo de datos entre funciones ni lee RAM del mando.

La fase aporta una conclusión técnica útil: varios candidatos de las fases anteriores **son consultas de modo/estado**, no inicializadores de los campos de configuración. Sigue **sin verificarse** la inclusión de clase 10 en la configuración USB real.

## 1. De una palabra en flash a una referencia de código

El paso más relevante respecto a la fase 50 es discriminar entre:

- **Dato literal:** la palabra de 32 bits de la imagen firmada contiene \`0x2000A2A8\`. Es evidencia de su existencia, no de que se ejecute una instrucción que la lea.
- **Carga relativa a PC:** la instrucción OEM \`LDR Rx,[PC,#disp]\` calcula exactamente una de esas posiciones de literal, usando \`((PC+4) & ~3) + disp\`.
- **Escritura atribuible:** después de la carga, el análisis conserva únicamente alias de registros que puede seguir en línea recta; se detiene ante bifurcaciones, llamadas o redefiniciones que podrían invalidar el vínculo.

El código encuentra **11 candidatos de carga** en los puntos originales \`0x60041E90\`, \`0x6005ABF2\`, \`0x6005ACC0\`, \`0x6005ACCC\`, \`0x6005ACDA\`, \`0x600610EA\`, \`0x60065446\`, \`0x60071416\`, \`0x60074AF8\`, \`0x60074E56\` y \`0x60079D7C\`.

Estos candidatos cargan un puntero a través de un literal concreto. **Solo el cálculo del literal no demuestra que toda la secuencia fuera del CFG sea alcanzable**, especialmente cerca de datos embebidos que un desensamblador puede interpretar como instrucciones. Las anclas conocidas de funciones firmadas y los ejemplos de flujo de las fases anteriores son la evidencia de mayor confianza.

## 2. Seguimiento de llamadas — lo que realmente hacen algunos de los destinatarios

| Función firmada inspeccionada | Datos originales relevantes | Evaluación |
|---|---|---|
| \`0x600D4E64\` | Lee \`[R0+0x90]\` y \`[R0+0x98]\` | Consultas de modo y motor USB; no escritor local de clases |
| \`0x600D5512\` | Lee \`[R0+0x90]\` y \`[R0+0x104]\` | Consulta de modo/estado |
| \`0x600D546A\` | Lee \`[R0+0x9C]\` | Consulta de otro campo auxiliar |
| \`0x60060FE8\` | Guarda R0 en R4, comprueba el modo y puede llamar a \`0x60060F84\` | Transición condicional que reutiliza el objeto |
| \`0x60079D7C\` → \`0x6007EB8C\` | La primera carga \`owner\` en **R2**, mientras que la segunda hace escrituras en **[R0]** y **[R0+4]** | **No** se puede atribuir esa escritura a \`owner+4\`: cambia el argumento base |

El caso del último renglón es especialmente importante: un código vecino muestra una escritura con desplazamiento **+4**, pero no basta con que una función también haya recibido el puntero \`owner\` en otro registro. Atribuirla automáticamente al objeto USB produciría un falso hallazgo.

Algunos wrappers firmados son saltos o *veneers* que no escriben campos. Se observaron llamadas o saltos hacia \`0x6004C374\`, \`0x600D4E64\`, \`0x600D5512\`, \`0x60060FD0\`, \`0x600D546A\`, \`0x600D5482\`, \`0x600D5578\` y \`0x6007EB8C\`. **La inspección de una ventana próxima a cada destino no equivale a un CFG completo.**

## 3. Direcciones conocidas, valores todavía desconocidos

La ruta firmada del modo 2 utiliza el objeto \`owner = 0x2000A2A8\`, localizado en fase 50. Tras la construcción de configuración analizada en fase 49, los campos interpretados por el distribuidor de clase son:

| Campo de \`owner\` | Dirección RAM | Datos por demostrar |
|---|---|---|
| \`owner+4\` | \`0x2000A2AC\` | Puntero al array de registros de clase activos |
| \`owner+8\` | \`0x2000A2B0\` | Método dinámico de configuración |
| \`owner+12\` | \`0x2000A2B4\` | Byte de cantidad de registros |

El hecho de que exista una estructura de clase 10 firmada en otra parte de la imagen OEM no acredita que \`owner+4\` apunte a ella. **No existe captura de la RAM del dispositivo y no se ha probado un escritor completo de esos campos.**

## 4. Implicación para el objetivo de firmware propio

Se ha reducido el número de rutas plausibles en los alrededores de las referencias literales a \`owner\`. Podemos descartar varias funciones de **consulta de modo/estado** como *escritores locales directos* de los campos de clase. No se ha demostrado la presencia de la clase 10 en una configuración física activa, ni la ejecución de código propio, una vía de control arbitrario sobre punteros de función, ni la superación de **HAB CLOSED**.

La investigación de la ROM OEM sirve para comprender el sistema y seleccionar experimentos, pero conviene impedir que fases con hallazgos puramente estáticos se interpreten como progreso proporcional hacia instalar firmware no firmado.

## Decisión y siguiente objetivo

**Fase 52 recomendada: una vía de comprobación de la configuración activa**, mediante una de estas dos opciones, en orden prudente:

1. Reconstruir un **CFG/interprocedural** explícito de las funciones que reciben \`owner\` por R0/R1/R2, identificando cualquier escritor efectivo \`owner+4/+8/+12\`, con propagación validada y paradas ante ramas desconocidas.
2. Si el CFG no permite recuperar datos de ejecución, planificar una **captura pasiva y reversible de enumeración USB y descriptores** del mando. Las solicitudes estándar de solo lectura pueden corroborar interfaces activas, pero no equivalen a leer los objetos internos RAM ni prueban clase 10 por sí mismas.

No se recomiendan cambios de flash/eFuses ni pruebas de modificación destructiva mientras no exista una vía fiable de recuperación.

## Reproducibilidad

\`\`\`bash
python -m unittest tests.test_bruce_owner_alias_writers_phase51 tests.test_bruce_owner_transitive_phase51 tests.test_bruce_owner_mode_guards_phase51 -v

python -m tools.audit_bruce_owner_alias_writers_phase51 bruce_pvt_a_prod_signed.bin --out phase51-aliases.json
python -m tools.audit_bruce_owner_transitive_phase51 bruce_pvt_a_prod_signed.bin --out phase51-callees.json
python -m tools.audit_bruce_owner_mode_guards_phase51 bruce_pvt_a_prod_signed.bin --out phase51-modes.json
\`\`\`

Imagen original OEM firmada obligatoria SHA-256: \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[PR #53](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/53).
