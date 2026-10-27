# Selección de aplicaciones A/B — fase 12

[English](../en/application-selection.md) · [Traspaso](traspaso.md)

Esta fase modela la función 0x60801EF0..0x60801F4A a partir de las instrucciones publicadas del bootloader build 169429 (imagen SHA-256 59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0). La secuencia de 90 bytes tiene SHA-256 3d167008abac66682b155fc2ee091c34811cdd70517fda34b3b0853df5787afe.

El analizador comprueba la huella, instrucciones y literales antes de construir escenarios. **No emula la CPU ni usa el mando.**

| Selector en r0 | Aplicación validada mediante 0x6080200C | Si valida | Si falla |
|---|---|---|---|
| 2 | 0x60040000 (A) | Prepara VTOR, MSP, PSP y salto al reset handler | Escribe 0x10 en 0x400F8038 y retorna |
| 3 | 0x60840000 (B) | Lo mismo para B | Escribe 0x20 en 0x400F8038 y retorna |
| Otro | No se valida ninguna | — | Retorna sin seleccionar |

El validador debe devolver cero en su byte bajo para seguir al salto. La dirección 0x400F8038 es el registro GPR7 de estado, **no flash**. Esto no demuestra reinicio ni recuperación automática. La procedencia de los identificadores 2/3 queda por determinar.

## Reproducción

    python tools/audit_application_selection.py
    python -m unittest discover -s tests -v

Los seis escenarios son **sintéticos**: un modelo de flujo basado en instrucciones verificadas, no pruebas físicas, emulación ARM, ejecución de firmware propio ni elusión de autenticación.

**Siguiente paso:** seguir los llamadores de 0x60801EF0 y los lectores/escritores de GPR7 en el binario local con hash coincidente para comprobar si existe selección tras fallo.
