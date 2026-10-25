# Fase 12 — Auditoría verificable de la ruta al escritor IVT

**Alcance:** bootloader A build 169429, SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. Análisis **offline**, exclusivamente de los intervalos de instrucciones publicados en `evidence/bootloader-analysis.json`.

## Avance comprobable

`tools/trace_write_path.py` examina el registro de instrucciones existente, exige que coincidan los saltos, comprueba que las tablas virtuales mantienen sus destinos y genera un informe JSON. No necesita un binario propietario completo. No accede al USB ni realiza escrituras.

Con el descriptor IVT `0x12` reconstruido en la fase 11, audita la siguiente cadena:

| Origen | Llamada y destino | Evidencia |
|---|---|---|
| `0x6080285C` | `BL` en `0x608028C6` → `0x60801ED0` | Llamada directa |
| `0x60801ED0` | `BL` en `0x60801EE4` → `0x60801DD4` | Llamada directa |
| `0x60801DD4` | `BL` en `0x60801E62` → `0x60801D9C` | Lectura IVT candidato |
| `0x60801D9C` | `BL` en `0x60801DC0` → `0x60801D40` | Preparación/escritura IVT |
| `0x60801D40` | `BLX R4` en `0x60801D98` → `0x6080B0F0` | **Condicional:** tabla `0x60815300`, slot 2, contexto IVT |
| `0x6080B0F0` | `BX IP` en `0x6080B132` → `0x60808E38` | **Condicional:** tabla física `0x60815320`, slot 6 |

`0x60801D40` carga el método desde el desplazamiento `+8` de la tabla del objeto. El constructor documentado en la fase 11 instala `0x60815300` en el descriptor IVT. `0x6080B0F0` pasa por la comprobación de rango `0x6080AA7C` antes de preparar la llamada al método físico. **Los destinos indirectos no se resuelven genéricamente:** dependen del objeto construido en el análisis previo.

La operación IVT examinada fija `offset = 0` y `longitud = 0x1000` (4096 bytes). Se validan las instrucciones que establecen los argumentos, la tabla y el búfer de respaldo. No existe una entrada externa identificada que sustituya el offset por `0xFFFFFFF0`, valor empleado en la emulación sintética de fase 11.

## Qué no demuestra

- Que `0x6080285C` sea invocable desde USB, Bluetooth o un usuario.
- Que los argumentos sintéticos utilizados en emulación lleguen al escritor físico.
- Que el backend acepte una escritura fuera de partición.
- Que las firmas RSA o HAB puedan eludirse.
- Que el código revisado sea completo: la evidencia cubre **regiones seleccionadas**.

**HAB CLOSED sigue siendo una medición del mando analizado. No hay ejecución propia demostrada.**

## Reproducción

Desde la raíz del repositorio:

```sh
python tools/trace_write_path.py > phase12-report.json
python -m unittest discover -s tests -v
```

El informe identifica las llamadas directas fuera de la selección, los saltos `BLX` no resueltos automáticamente y la ausencia de demostración de accesibilidad desde interfaces externas.

## Próximo trabajo

1. Obtener un mapa verificable del despacho USB/diagnóstico del bootloader A a partir del binario local verificado por SHA.
2. Comprobar si algún argumento externo alcanza métodos de almacenamiento, sin inferirlo de una ruta interna de actualización.
3. Reconstruir completamente selección A/B y restauración antes de considerar pruebas físicas.
4. Separar siempre **medido**, **estático condicionado**, **emulado** e **hipótesis**.

No se propone escribir firmware ni entrar en recuperación en esta fase.
