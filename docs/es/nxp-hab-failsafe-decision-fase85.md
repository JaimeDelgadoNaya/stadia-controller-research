# Línea NXP — fase 85: llamadores de `failsafe` y decisión GO/NO-GO

**27 de octubre de 2026.** Continuación acotada de la [fase 84](nxp-hab-rvt-literales-fase84.md). El objetivo no es acumular más coincidencias, sino evaluar si la ruta original de `failsafe` aporta una vía verificable de consulta de HAB o ejecución de firmware propio. El análisis es **exclusivamente offline**.

## Evidencia previa confirmada

La aplicación Bruce firmada contiene, en `0x60040726`, las instrucciones originales que cargan la tabla HAB `0x00200300` y saltan mediante su **entrada `failsafe` (`+0x28`)**. La función `get_version` está en otra entrada (`+0x30`). El código del bootloader A extraído previamente emplea `entry`, `authenticate_image_no_dcd` y `exit` para autenticar una imagen adicional, tal como se recoge en [la reconstrucción de la cadena de arranque](arranque.md). En la unidad física se midió HAB CLOSED.

## Auditoría de la fase 85

El [analizador reproducible](../../tools/audit_hab_failsafe_callers_phase85.py) vuelve a exigir **tamaño y SHA-256 de la aplicación Bruce original** y los bytes exactos del stub firmado de la fase 84. A continuación inspecciona la región anterior al CSF para localizar:

- Palabras little-endian `0x60040726` o `0x60040727` que podrían ser punteros hacia ese stub.
- Codificaciones Thumb compatibles con saltos directos a `0x60040726`, decodificadas desde posibles comienzos alineados a dos bytes mediante Capstone.

El barrido *no verifica* límites efectivos de instrucciones, caminos de ejecución, referencias indirectas, saltos por registros o direcciones reconstruidas dinámicamente; una coincidencia podría ser simplemente un dato.

[**Resultado de CI sobre la imagen original verificada por SHA-256**](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40568935912):

| Evidencia buscada en Bruce firmada | Resultado |
|---|---:|
| Palabras puntero directas a la rutina `failsafe` del stub | **0** |
| Saltos Thumb directos decodificados hacia el stub | **0** |
| Llamadores ejecutados o accesibles desde USB, acreditados por esta fase | **0** |
| Versión HAB leída desde ROM | **No** |

El workflow pasó **52 pruebas sintéticas acumuladas** de las fases NXP 81–85, junto al análisis de dos archivos OEM públicos originales. No se realizó ninguna prueba sobre hardware.

## Decisión técnica

**NO-GO provisional para seguir invirtiendo fases en este stub `failsafe` como vía de ejecución de firmware propio.**

Motivo: se ha demostrado una ruta **de salida hacia la función de error de ROM**, no una lectura `get_version` ni un callback controlado desde el host; este barrido adicional no ha acreditado llamadores directos ni punteros. **NO-GO no significa imposibilidad universal**: pueden existir llamadas indirectas o rutas no examinadas.

**Estado de la rama HAB:** mantener como línea secundaria a la espera de alguna de estas evidencias independientes: lectura de la versión de HAB, una llamada documentada y realmente alcanzable a `authenticate_image_no_dcd` con un contexto relevante, una prueba nueva de validación ROM o un mecanismo de recuperación seguro. La vulnerabilidad histórica de HAB y [CVE-2022-45163](https://community.nxp.com/t5/i-MX-Security/SDP-Read-Bypass-CVE-2022-45163/ta-p/1553565) siguen siendo asuntos distintos; una fuga potencial de memoria no implica ejecución autenticada.

**Próxima prioridad fuera de esta rama:** analizar funciones de actualización o funcionamiento compatibles con la seguridad existente, pero sin considerar la firma eludida ni asumir un firmware instalable. El archivo privado `bootloader-a.bin` **no estaba disponible en esta sesión** para un nuevo censo binario; solo se ha usado la evidencia firmada previamente documentada. No se publicaron binarios propietarios, memoria del dispositivo o identificadores, ni se realizaron escrituras de flash/eFuses.

## Reproducción

```sh
python -m unittest tests/test_hab_failsafe_callers_phase85.py -v
python -m tools.audit_hab_failsafe_callers_phase85 local/bruce_pvt_a_prod_signed.bin --out local/failsafe-callers.json
```

[Herramienta](../../tools/audit_hab_failsafe_callers_phase85.py) · [pruebas](../../tests/test_hab_failsafe_callers_phase85.py) · [evidencia saneada](../../evidence/nxp-hab-failsafe-callers-phase85.json).
