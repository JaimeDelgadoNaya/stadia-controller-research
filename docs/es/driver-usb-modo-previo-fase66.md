# Fase 66 — Driver USB original, guarda MMIO y escritor de modo previo

**26 de octubre de 2026.** Análisis offline de Bruce OEM, SHA-256 obligatorio `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Continúa la [fase 65](instancia-clase10-fase65.md).

## Qué cambia

Se ejecutan el **driver original `0x6005556C` y su inicializador `0x60055400`**, en lugar de imponerles un retorno. La condición externa se hace explícita: un bloque MMIO virtual en `0x402E0000`, sembrado con valores sintéticos y sin efectos reales de periférico.

También se identifica un llamador de la rutina `0x60060F28`, que escribe **1 en `owner+0x90`** antes de otra llamada externa. Un experimento por etapas utiliza esa escritura y ejecuta las guardas originales de transición al modo 2. El enlace a la instancia de clase 10 se reproduce con la palabra MMIO virtual 8; con 7, el driver original devuelve error y bloquea ese enlace.

Esto reduce dos inyecciones de fases anteriores, **pero no reproduce hardware físico ni el arranque completo**. No se ha leído ese registro del mando.

## Guarda del driver original

El método `0x6005556C` solo acepta R0=2 en este destino. Para otro modo devuelve **6** antes de leer MMIO. Con modo 2:

1. Carga la base literal `0x402E0000`.
2. Lee la palabra de **`base+0x124 = 0x402E0124`**.
3. Conserva sus cinco bits bajos mediante AND `0x1F`.
4. Si el resultado es **menor o igual que 7**, devuelve **1**.
5. Para 8–31, ejecuta el inicializador original, publica el puntero `0x20011DFC` y devuelve cero en el modelo virtual.

No se asigna un nombre oficial ni significado de hardware a ese registro en esta auditoría. Las conclusiones son sobre la dirección, máscara y condición verificadas en el código.

| Modo sintético | Palabra virtual | Tras máscara `0x1F` | Retorno original | Inicializador `0x60055400` |
|---:|---|---:|---:|---|
| 2 | `0x00` | 0 | 1 | No |
| 2 | `0x07` | 7 | 1 | No |
| 2 | `0x08` | 8 | **0** | Sí |
| 2 | `0x1F` | 31 | **0** | Sí |
| 2 | `0x108` | 8 | **0** | Sí |
| 2 | `0x100` | 0 | 1 | No |
| 3 | `0x08` | 8 | 6 | No |

En los casos aceptados, las instrucciones originales establecen el objeto de driver **`0x20011DFC`**, su contexto **`0x200063C0`**, las estructuras de cola y las escrituras a offsets MMIO como `+0x140`, `+0x148`, `+0x154`, `+0x158` y `+0x1A8`. La evidencia incluye cada lectura/dirección y escritura MMIO. Son accesos **exclusivamente virtuales**.

## Escritor del modo previo 1

La rutina de activación `0x60074658` conserva su argumento R0 en R5. El fragmento que comienza en `0x60074772` calcula:

```text
R7 = R5 + 0x3DC0 + 0x28
si R5 = 0x200064C0, R7 = owner = 0x2000A2A8
```

Tras llamadas auxiliares, `0x600747B0` mueve R7 a R0 y `0x600747B2` llama a **`0x60060F28`**. En esa función, `0x60060F28 MOVS R3,#1` y **`0x60060F2C STR.W R3,[R0,#0x90]`** escriben 1 en **`0x2000A338`**.

La prueba comienza en el fragmento de llamador con R5/base global y R6/stack sintéticos, coherentes con las instrucciones fijadas. No se sigue el argumento real de toda la activación desde su llamador anterior. Cuatro helpers de registro se sustituyen por operaciones sin efectos con retorno cero. Se ejecutan el cálculo de owner, BL y escritura originales.

La ejecución **se detiene antes de `0x60060F34 BL 0x6009267C`**. Esa llamada pendiente, su retorno, efectos y posible fallo no se reproducen. Por ello no se afirma que la rutina haya completado su activación ni que el campo vaya a conservar siempre 1.

## Composición con transición, driver y clase 10

La segunda etapa parte explícitamente de la RAM virtual tras esa escritura y llama a `0x60060FE8` solicitando modo 2. No se ejecuta la llamada pendiente `0x6009267C` entre ambas etapas. El helper de transición `0x60060C70` sigue siendo un stub sin efectos. Las instrucciones de las guardas, la escritura transitoria de modo, el owner, motor, driver, selector e inicializador de clase 10 se ejecutan desde la imagen OEM.

| Estado de entrada | Registro MMIO virtual | Resultado observado |
|---|---|---|
| Snapshot fase 64, modo previo 0 | 8 | La transición retorna antes de llegar a clase 10 |
| Tras escritura original de modo 1 | 8 | Driver original publica `0x20011DFC`; el primer registro recibe instancia **`0x200040E0`** |
| Tras escritura original de modo 1 | 7 | Driver original devuelve **1**; no llega al inicializador de clase 10 |

En el caso aceptado, la transición permanece en su estado **transitorio 1** al detener la prueba; la solicitud fue 2. Se para tras la primera clase, antes de las otras tres y antes de publicar el modo final. **No es una demostración de transición completa al modo 2.** El caso de error se detiene antes de cleanup; no acredita su estado final.

## Límites que permanecen

- MMIO es memoria virtual ordinaria: no modela efectos de lectura/escritura, bits de estado reales, relojes, resets, DMA ni tiempos del periférico.
- Se heredan los modelos de dependencias del constructor de fase 64 y los helpers de guardado/restauración de fase 65.
- El join entre escritor y transición omite `0x6009267C`; el llamador completo y su estado real siguen pendientes.
- No se ejecutan las otras clases, publicación final de modo, callbacks OEM ni cleanup de error.
- El valor real de `0x402E0124`, la activación física de clase 10 y el camino de paquetes físicos hasta su callback no se han medido.

## Reproducción y validación

```powershell
python -m tools.audit_usb_driver_phase66 local/bruce.bin --out local/phase66.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_driver_phase66 -v
```

Requiere `requirements-emulation.txt` y el archivo OEM exacto obtenido por separado del [archivo de firmware](https://github.com/StadiaMemories/firmware). Se verifican SHA, instrucciones, literales MMIO y el escritor. Las pruebas negativas alteran la rama de guarda, base MMIO y STR de modo. **738 pruebas locales pasan**, incluidas las habilitadas contra el original; CI reproduce y compara la evidencia. Las opciones nuevas de la herramienta de fase 65 mantienen su salida anterior intacta con los valores por defecto.

El siguiente objetivo es resolver la llamada pendiente **`0x6009267C`**, las condiciones del llamador de activación y los efectos requeridos del helper de transición. La hipótesis física continúa abierta: ejecutar instrucciones contra memoria virtual no demuestra que una controladora real acepte la misma secuencia.

No se han enviado comandos USB, leído/escrito registros físicos, cambiado firmware/eFuses, ejecutado código propio en el mando ni superado HAB CLOSED.

[Evidencia](../../evidence/usb-driver-mode-phase66.json) · [Auditor](../../tools/audit_usb_driver_phase66.py)
