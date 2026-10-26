# Fase 49 — Construcción de la configuración USB y procedencia de la lista de clases

**26/10/2026 · PR #51 · Auditoría offline de la actualización OEM Bruce firmada exacta.**

## Hallazgo principal

Hemos reconstruido **quién escribe la configuración compartida en RAM** y cómo se transmite su puntero desde un objeto superior. El registro de clase 10 existe en el archivo de actualización y su ruta de eventos está validada estáticamente (fases 43–48), pero esta fase **no demuestra que pertenezca a la configuración USB activa del mando**.

La rutina firmada **\`0x600550E4\`** toma R1 como puntero de configuración, lo conserva en R4, y lo escribe en **\`[0x20004080+4] = 0x20004084\`**:

\`\`\`asm
0x600550EA  MOV R4,R1
0x60055104  LDR R3,[PC,#0xA0]      ; literal 0x600551A8 = 0x20004080
0x6005510C  MOV R5,R3
0x6005512E  STR R4,[R5,#4]         ; singleton USB +4 = puntero de configuración
\`\`\`

La ruta está condicionada por comprobaciones de punteros, estado del singleton y devoluciones de funciones de inicialización. **No es una prueba de que haya ejecutado la escritura en un mando físico.**

### Llamador firmado y campos de entrada

La función original **\`0x60060F84\`** llama al constructor en **\`0x60060F90\`**. Si su argumento de entrada es un objeto de propietario \`owner\`, prepara:

| Campo original | Dirección relativa | Propósito deducido del código |
|---|---|---|
| \`owner+4\` | Configuración pasada como R1 | Puntero que termina en \`[0x20004084]\` |
| \`owner+8\` | \`config+4\` | Valor de método usado por el despacho indirecto \`0x600D0BFA\` |
| \`owner+12\` | \`config+8\` | Byte que lee el distribuidor como cantidad de registros |
| \`owner+0x10\` | Byte pasado como R0 | Modo/identificador para el constructor |
| \`owner+0x98\` | Dirección pasada como R2 | Destino para puntero de motor USB |

Anclajes:

\`\`\`asm
0x60060F86  ADD.W R2,R0,#0x98
0x60060F8A  ADDS R1,R0,#4
0x60060F8E  LDRB R0,[R0,#0x10]
0x60060F90  BL 0x600550E4
\`\`\`

Una llamada directa a ese constructor de propietario procede de **\`0x6006102E\`**. El código firmado atribuye por tanto el puntero \`config\` a un **objeto RAM de nivel superior**, no a la propia tabla ROM de clases \`0x60104B74\`.

**Límite:** no conocemos la dirección final de \`owner\`, el valor de sus campos, ni si este camino es el usado por la configuración activa de un mando físico.

## Inicialización interna del motor USB

La función compartida carga otros tres literales verificables en el archivo firmado:

| Dirección de literal OEM | Valor original | Función |
|---|---|---|
| \`0x600551A8\` | \`0x20004080\` | Singleton USB común |
| \`0x600551AC\` | \`0x200040A0\` | Puntero de estructura auxiliar, escrito en singleton +8 |
| \`0x600551B0\` | \`0x600D0BC9\` | Callback OEM para el motor USB |
| \`0x600551B4\` | \`0x60104B74\` | Tabla ROM de métodos por clase |

Después de guardar el puntero de configuración, la ruta llama **\`0x60055138: BL 0x60055350\`**. Su código usa literales adicionales:

- **\`0x600553F8\`** contiene la dirección RAM de instancia del motor **\`0x200063C0\`**.
- **\`0x600553FC\`** contiene el puntero de tabla de funciones OEM **\`0x60104BC4\`**, cuya primera palabra es **\`0x6005556D\`**.
- **\`0x600553A0\`** almacena el callback firmado \`0x600D0BC9\` en un campo del objeto motor.
- **\`0x600553C0\`** guarda la tabla OEM \`0x60104BC4\` como función/vtable en el motor.
- **\`0x600553C2\`** escribe el puntero a la instancia del motor a través de la dirección de salida proporcionada por el constructor. Si este último se invoca con sus literales firmados, la dirección de salida es **\`0x20004080\`**.
- **\`0x600553CA: BLX R3\`** utiliza la primera función de la tabla original para inicializar el motor. No es un salto a código aportado por el ordenador.

Los literales y las instrucciones anteriores están anclados a la imagen exacta, pero la **ejecución y resultado de la inicialización no se han medido**.

## ¿Y la clase 10?

La fase 48 demostró que el distribuidor de clases **\`0x6005505C\`** usa la misma configuración \`[0x20004084]\`:

- \`config+0\`: puntero a array de registros runtime de 12 bytes.
- \`config+8\`: cantidad de registros.
- Por cada registro, se lee un selector desde un descriptor. Si es **10**, el distribuidor puede escoger el método firmado **\`0x600D0E59\`** desde la tabla OEM de métodos.
- \`config+4\`: método dinámico utilizado por la otra ruta de control **\`0x600D0BFA\`**.

Esta fase identifica la procedencia de **\`config\`**, pero **no** los valores reales de su puntero a registros, del byte contador o del método. El hecho de que exista un registro inicializado con descriptor de clase 10 en **\`0x200030F4\`** no significa que la configuración activa lo incluya.

### Evidencia que falta

El punto decisivo pasa a ser **la inicialización del objeto propietario** de \`0x60060F84\`: quién escribe sus campos \`+4\`, \`+8\` y \`+12\`, cuáles son los descriptores de la configuración real y qué rama se ejecuta al conectar el controlador.

Todavía no se ha demostrado:
- Ruta física USB EP0 → registro activo clase 10.
- Callback secundario clase 10 instalado durante una sesión real.
- Escritura de punteros de código arbitrarios controlada por un host.
- Ejecución de firmware propio, bypass HAB CLOSED o funcionamiento nativo Xbox/Switch 2.

No se ha enviado ninguna petición USB ni escrito flash/eFuses, y la fuente no es un volcado completo del chip.

## Decisión para la fase 50

Investigar la **construcción y los escritores del objeto \`owner\`**, desde el llamador \`0x6006102E\` hacia las asignaciones de \`owner+4\`, \`owner+8\` y el byte de conteo en \`owner+12\`. Buscar una lista de clases realmente **seleccionada**, no simplemente una tabla ROM de opciones disponibles. Si la información depende exclusivamente del runtime, priorizar una observación pasiva USB y una ruta de recuperación garantizada antes de cualquier prueba activa.

## Reproducir

\`\`\`bash
python -m unittest tests.test_bruce_runtime_usb_config_phase49 tests.test_bruce_usb_config_writer_phase49 -v
python -m tools.audit_bruce_runtime_usb_config_phase49 local/bruce_pvt_a_prod_signed.bin --out local/phase49-survey.json
python -m tools.audit_bruce_usb_config_writer_phase49 local/bruce_pvt_a_prod_signed.bin --out local/phase49-writer.json
\`\`\`

Los auditores rechazan cualquier fichero que no coincida exactamente con SHA-256 **\`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`**. [PR #51](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/51).
