# Fase 25 — Análisis de dos destinos de punteros dinámicos

**Muestra:** bootloader A original de Stadia (build 169429, 131.072 bytes), SHA-256
\`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0\`.

La inspección se realizó **offline** sobre la copia privada: sin comandos USB,
borrado o programación flash, alteraciones de eFuses ni modificación del mando.
Se usó \`llvm-objdump --triple=thumbv7em-none-eabi\` para analizar instrucciones
del fichero local; el verificador de fase 25 confirma huellas y bytes exactos.

## Hallazgo 1: \`0x60809048\` opera sobre un puntero desconocido

Se llega a esta función desde varias llamadas de la fase 24. Sus argumentos
R0 provienen de **valores cargados**, según la ruta, de
\`global+0x560\`, \`global+0x568\` o \`global+0x570\`, donde
\`global=0x20008B78\`. **No sabemos a qué direcciones apuntan esos valores.**

En el intervalo \`0x60809048..0x60809174\` se observan:

- \`0x6080904C\`: \`R5=R0+0xA4\`; \`0x60809052\`: \`R4=R0\`.
- Lecturas desde \`R4+0x158\` y \`R4+0x15C\`, y más adelante
  desde \`R4+0x154\`.
- Preparación de argumentos \`R4+0x6C\` y \`R4+0xF8\` para otras
  funciones.
- Llamadas internas a \`0x608101AA\`, \`0x608101BC\`,
  \`0x608041F0\`, \`0x60808E7C\` y \`0x6081022C\`.

En ese intervalo **no aparece una escritura directa a un campo del objeto
identificado mediante R4**; las operaciones \`STR\` locales observadas
preparan parámetros en la pila. Pero **sí hay llamadas a otras funciones**
que pueden tener efectos sobre el objeto y no se han seguido por completo.

Esta evidencia no demuestra que la rutina procese directamente
un paquete del host, ni que ese objeto sea el contexto de un callback USB.

## Hallazgo 2: \`0x608109FE\` es una operación de desenlazado

La función contiene una secuencia característica de eliminación de nodo
de una lista doblemente enlazada:

| Dirección | Operación observada |
|---|---|
| \`0x608109FE\` | Obtiene anterior y siguiente desde \`[R0+4]\` y \`[R0+8]\` |
| \`0x60810A02\` | Obtiene un puntero propietario desde \`[R0+0x10]\` |
| \`0x60810A04\` | Escribe el siguiente en \`[anterior+8]\` |
| \`0x60810A08\` | Escribe el anterior en \`[siguiente+4]\` |
| \`0x60810A10\` | Actualiza condicionalmente \`[propietario+4]\` |
| \`0x60810A14\` | Pone a cero \`[nodo+0x10]\` |
| \`0x60810A1A\` | Guarda el contador decrementado en \`[propietario]\` |

**Son escrituras reales en direcciones derivadas de punteros RAM**, no
direcciones absolutas conocidas. Identificar una operación de lista
no determina dónde están sus nodos.

## Procedencia desde \`0x60811DC8\`

El llamador carga primero un puntero desde \`[contexto+0xC]\` y luego
otro desde \`[puntero_anterior+0xC]\`.

- \`0x60811DE2\`: llama a \`0x608109FE\` con \`link+0x18\`.
- \`0x60811DF0\`: en otra condición, llama con \`link+0x04\`.

La fase 24 asoció la entrada de esa cadena a un subobjeto derivado de
\`global+0x59C\`. **Los dos niveles de carga dinámica impiden identificar
el nodo final solo con su offset en la estructura global.**

## Resultado para los callbacks

Los cuatro campos investigados siguen siendo \`0x20009170\` (IN handler),
\`0x20009174\` (contexto IN), \`0x20009178\` (OUT handler) y
\`0x2000917C\` (contexto OUT).

**No se demuestra que ningún objeto recibido en estas rutas corresponda
a esas cuatro direcciones.** Tampoco se demuestra lo contrario; las
direcciones de los objetos en tiempo de ejecución y el efecto de los
métodos llamados siguen pendientes.

**No hay ruta USB de host a escritura flash demostrada, firmware propio
en ejecución ni elusión de HAB CLOSED.**

## Reproducción

\`\`\`powershell
py tools/audit_dynamic_pointer_sinks.py local/bootloader-a.bin --out local/phase25.json
py -m unittest discover -s tests -v
\`\`\`

El script \`tools/audit_dynamic_pointer_sinks.py\` comprueba el SHA del archivo
completo, los SHA de tres regiones y una selección de instrucciones y
destinos de llamadas directas. GitHub Actions solo usa pruebas sintéticas;
la copia del bootloader no está subida.

## Investigación siguiente

La fase 26 debería reconstruir **la procedencia de los valores guardados
en \`global+0x560/+0x568/+0x570\`** y la asignación inicial de los
punteros de lista de \`global+0x59C\`. Es más informativo que buscar
otra vez patrones de \`STR\` sin saber el objeto al que apuntan.
