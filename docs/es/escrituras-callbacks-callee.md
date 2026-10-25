# Fase 24 — Escrituras en subobjetos y procedencia de punteros

**Muestra local:** bootloader A Stadia, build 169429, 131.072 bytes.
SHA-256: \`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0\`.
El binario no se sube a GitHub. La inspección se hizo offline con desensamblado Thumb de LLVM y huellas SHA-256 de los intervalos examinados.

## Resultado principal

Se revisaron los cuatro destinos de la fase 23 y la cadena de inicialización que sale de \`0x60809D98\`. En los intervalos examinados se contabilizan **23 escrituras directas con dirección calculable** a través de alias conocidos. **Ninguna solapa los cuatro campos de callback USB**:

- IN handler: \`global+0x5F8\` = \`0x20009170\`
- IN context: \`global+0x5FC\` = \`0x20009174\`
- OUT handler: \`global+0x600\` = \`0x20009178\`
- OUT context: \`global+0x604\` = \`0x2000917C\`

Esto es un resultado acotado, no una prueba de que ningún otro camino pueda cambiarlos.

## Escrituras observadas

| Función / bloque | Desplazamientos respecto a \`0x20008B78\` | Interpretación |
|---|---|---|
| \`0x6080A990\` | \`+0x574\` (dos sitios) | Campo del subobjeto recibido |
| \`0x6080990C\` | \`+0x6C0\` | Estado del controlador; no es \`+0x6C4\` ni un callback |
| \`0x60809D98\` | \`+0x588\` | Campo de estado del subobjeto |
| \`0x60810210\` | \`+0x5DC\` | Resultado/miembro del objeto auxiliar |
| \`0x60810BB8\` | \`+0x58C, +0x5C8, +0x5CC, +0x5D2, +0x5D8\` | Inicialización de objeto auxiliar |
| \`0x60810B38\` | \`+0x590, +0x594, +0x598, +0x5C4, +0x5D0, +0x5D1\` | Inicialización de subobjeto |
| \`0x6081099C\` | \`+0x59C, +0x5A0, +0x5A4, +0x5A8, +0x5AC\` | Inicialización de nodo |
| \`0x6081099C\` (segundo objeto) | \`+0x5B0, +0x5B4, +0x5B8, +0x5BC, +0x5C0\` | Inicialización de otro nodo |

Los campos del callback empiezan en \`+0x5F8\`; los stores de la cadena auxiliar terminan en \`+0x5D8\`. El store de \`+0x6C0\` está fuera de esa zona.

## Flujo de punteros que sí queda demostrado

La cadena desde \`0x60809D98\` es:

1. Calcula \`global+0x58C\` y llama a \`0x60810210\`.
2. \`0x60810210\` lee y, en la rama de inicialización, escribe \`global+0x5DC\`; pasa \`global+0x58C\` a \`0x60810BB8\`.
3. \`0x60810BB8\` conserva el alias y llama a \`0x60810B38\`.
4. \`0x60810B38\` inicializa campos hasta \`+0x5D8\`, y pasa subobjetos \`global+0x59C\` a \`0x60811DC8\` y \`global+0x59C/+0x5B0\` a \`0x6081099C\`.
5. \`0x6081099C\` inicializa los dos nodos con los offsets de la tabla anterior.

En \`0x60811DC8\`, se lee un valor de \`global+0x5A8\`, se desreferencia ese valor y se llama a \`0x608109FE\` con un puntero derivado. **El destino final de ese puntero es dinámico y queda sin resolver.**

## Límites que importan

- \`0x6080A990\` y \`0x608021B4\` leen un valor de los campos \`global+0x568\` y \`global+0x560\`, respectivamente, y lo pasan a \`0x60809048\`. No se conoce estáticamente el destino de esos punteros.
- \`0x6080C150\`, llamado desde \`0x6080990C\`, reemplaza el argumento de entrada cargando otro puntero literal (\`0x20009DC0\`); no usa el alias recibido para escribir los callbacks.
- \`0x60802174\` lee campos del objeto global y contiene un bucle incondicional en \`0x608021A6\`; la ruta que llega ahí no retorna.
- Las funciones \`0x60809048\` y \`0x608109FE\` siguen pendientes de análisis por separado. El seguimiento de registros no demuestra que sus punteros dinámicos no puedan referenciar otras zonas.

**Conclusión:** en las funciones y bloques auditados no hay una escritura directa identificada sobre los campos de callback IN/OUT. No se ha demostrado un setter posterior, una ruta de host USB a escritura flash ni un bypass de HAB CLOSED.

## Reproducción

\`\`\`powershell
py -m pip install -r requirements.txt
py tools/audit_callee_store_provenance.py local/bootloader-a.bin --out local/phase24.json
py -m unittest discover -s tests -v
\`\`\`

El auditor verifica el hash completo y huellas de cada intervalo antes de desensamblar. Las pruebas de CI usan secuencias sintéticas; no contienen ni necesitan el binario propietario. El informe saneado \`evidence/usb-phase24.json\` conserva direcciones y huellas, no la imagen.
