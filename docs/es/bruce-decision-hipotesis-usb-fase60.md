# Fase 60 — Decisión sobre la hipótesis de callback/control desde USB

**26 de octubre de 2026.** Análisis completamente offline del firmware Bruce OEM original firmado. SHA-256 exigido: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Pregunta de investigación

La fase 58 identificó código firmado que escribe condicionalmente una pareja de **función y contexto** en dos palabras de la estructura SRAM cuyo literal base es `0x2000F878`:

- **`0x2000FBF4`** = `base+0x37C`: puntero con formato Thumb `0x600CE233` o `0x0000A9C5`.
- **`0x2000FBF8`** = `base+0x380`: contexto cero o puntero a objeto.
- La fase 59 resolvió el veneer `0xA9C4 → 0xB980` a la función XIP original **`0x6007E6A0`**, que trabaja con estados y atomics.

La hipótesis a comprobar era si alguna función lee o invoca este par como consecuencia de un evento USB.

## Experimento A — Alias locales de la base de la estructura

La imagen OEM contiene **10 candidatos PC-relativos** que cargan `0x2000F878` desde literales originales. El auditor fase 60 inicia una propagación de registros por **tramos lineales** a partir de cada carga. Mantiene bases y offsets literales de `MOV`, `ADD` y `SUB`. **Se detiene al encontrar una rama, una llamada o una redefinición que invalida el registro**; no supone que un nombre de registro identifique la misma instancia entre funciones.

El resultado firmado fue:

| Comprobación | Resultado |
|---|---|
| Cargas PC-relativas de la base auditadas | **10** |
| Escrituras a `0x2000FBF4` justificadas en tramos locales | **1**, `0x60063878` |
| Escrituras a `0x2000FBF8` justificadas en tramos locales | **1**, `0x6006387E` |
| Lecturas justificadas de cualquiera de los dos campos en esos tramos | **0** |

Las dos escrituras son controles positivos originales de la fase 58. El auditor **rechaza el resultado** si no las encuentra o si no identifica las 10 cargas ancladas al archivo firmado.

**Alcance del resultado negativo:** exclusivamente alias por instrucciones directas en tramos sin transferencias de control. **No descarta** consumidores mediante llamadas entre funciones, bases precalculadas, tablas de objetos, saltos indirectos, alias guardados en memoria o saltos condicionales.

## Experimento B — Referencias al código de callback y formas de llamada directa

Se buscaron palabras alineadas exactas con **bit Thumb** y las instrucciones con forma de `BL` en regiones originales XIP y ITCM (bytes de ITCM interpretados con su PC de ejecución). Resultados:

| Tipo de referencia | Coincidencias |
|---|---:|
| `0x600CE233` — rutina XIP `BX LR` sin efecto | **35** |
| `0x0000A9C5` — veneer ITCM de la función asociada al objeto | **1** |
| `0x6007E6A1` — destino real XIP contenido en el veneer de `0xB980` | **1** |
| **Total de literales** | **37** |
| Formas de `BL` directo a los cuatro destinos investigados | **0** |

La presencia repetida de la función sin efecto no significa que todas esas referencias se ejecuten. El único literal `0x6007E6A1` está en la tabla de salto original, en el desplazamiento de archivo `0xC1A0`. El `0xA9C5` aparece en `0x3E828`.

Un registro de callback puede invocarse mediante `BLX`, `BX` o carga al PC, sin `BL` directo. Por eso **cero coincidencias de `BL` no demuestra que jamás sea llamado**; solo acota la búsqueda.

## Decisión GO / NO-GO

**NO-GO para seguir tratando este par como una ruta de ejecución controlable por el host**, con las pruebas actuales.

- Tenemos productores firmados, dos escrituras al par, formatos Thumb y un manejador real de estado.
- **No tenemos lector/invocador verificado de esas dos palabras SRAM.**
- **No existe un camino acreditado desde un paquete USB de un ordenador a esa invocación**.
- No se ha medido la RAM instalada en un mando ni observado que esos manejadores se ejecuten.

**NO-GO no significa que esta vía sea imposible.** Significa que profundizar sin un puente de ejecución observable tiene menor valor que obtener evidencia dinámica o cambiar de ruta.

## Siguiente experimento recomendado: evidencia USB de solo lectura

La **fase 61** debería recopilar un informe de enumeración USB del mando real, de manera reversible, sin escribir firmware ni lanzar comandos de flasheo. En Windows puede utilizarse **USBView/USB Device Tree Viewer** para inspeccionar los descriptores que presenta el dispositivo y registrar las interfaces/endpoints. Para observar intercambios de enumeración ya existentes, una captura **USBPcap/Wireshark** debe limitarse a tráfico normal de conexión; evitar peticiones no estándar, actualizaciones, modo bootloader y acciones sobre memoria/eFuses.

La enumeración **no extrae el contenido de SRAM** ni demuestra por sí sola una ejecución de código. Sí sirve para contrastar las interfaces realmente activas con las rutas hipotéticas reconstruidas. El siguiente paso sería comparar los descriptores con las configuraciones OEM conocidas, sin alterar el mando. Se deben anonimizar identificadores de dispositivo o números de serie al publicar capturas.

En paralelo, una evaluación de un **puente externo Stadia→Xbox** puede ofrecer una solución más directa; los requisitos de autenticación de Xbox tendrían que evaluarse independientemente.

## Estado de seguridad y límites

No hemos ejecutado código personalizado, demostrado activación de clase 10, leído `owner+4/+8/+12` en RAM, superado HAB CLOSED ni logrado compatibilidad nativa Xbox/Switch 2. Esta fase **no envía comandos USB, no lee RAM instalada y no realiza escrituras flash ni eFuse**.

## Verificación

```bash
python -m unittest tests.test_bruce_pair_event_phase60 -v
python -m tools.audit_bruce_pair_event_phase60 local/bruce_pvt_a_prod_signed.bin --out local/phase60-pair-event.json
```

[PR #62](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/62) · [Evidencia estructurada](../../evidence/bruce-pair-event-phase60.json) · [Auditoría del firmware original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40371183749).

Los límites del desensamblado de posiciones candidatas permanecen explícitos: forma de código no equivale a alcanzabilidad, y coincidencia de literal no equivale a invocación real.
