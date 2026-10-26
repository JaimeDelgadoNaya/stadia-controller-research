# Fase 54 — Búsqueda interprocedural de escritores del objeto USB con controles positivos

**26/10/2026 · imagen original Bruce OEM firmada (SHA-256 fijado)**. Trabajo sin USB físico, sin modificar flash ni eFuses.

## Resultado: se verifican dos controles, pero no los tres escritores buscados

La fase 53 estableció las guardas de modo USB. Esta fase extiende el rastreo de **11 cargas PC-relativas verificadas** del literal `owner = 0x2000A2A8`, siguiendo saltos directos, llamadas con alias conocidos y *veneers* Thumb, con un límite estricto de estados.

**Resultado en el firmware OEM original:** el auditor no ha atribuido ninguna escritura a:

| Dirección RAM | Campo | Resultado del rastreo acotado |
|---|---|---|
| `0x2000A2AC` | `owner+4`, puntero al array de clases | 0 candidatos |
| `0x2000A2B0` | `owner+8`, método de configuración | 0 candidatos |
| `0x2000A2B4` | `owner+12`, recuento | 0 candidatos |

**No se demuestra que no existan escritores.** El barrido sigue solo rutas desde las 11 cargas directas conocidas, con llamadas indirectas no resueltas, un máximo de dos niveles de llamadas y `0x200` bytes por ventana. El origen `0x60071416` **agotó el límite de 10.000 estados** (10.001 contabilizados). También hay rutas que terminan en predicación `IT`, retorno indirecto y llamadas que el modelo no puede continuar con seguridad.

## Controles positivos originales: sí localiza escrituras conocidas

Para comprobar que el resultado cero no se debe simplemente a un rastreador incapaz de seguir el objeto, se exige localizar estas escrituras ya acreditadas:

```asm
; El objeto owner se carga por LDR PC en 0x60071416
; y se pasa por salto directo a 0x60060FE8.
0x6006101C  MOVS R7,#1
0x60061022  STR.W R7,[R4,#0x90]  ; escribe 1 en owner+0x90

0x60061070  STR.W R5,[R4,#0x90]  ; escribe el modo solicitado
```

**Resultado verificado sobre la imagen original**: se recuperan **los dos sitios** con destino efectivo `0x2000A338` y cadena `0x60071416 → 0x6007141C → 0x60060FE8`. El valor R7=1 se resuelve; el valor de R5 se marca **UNKNOWN**, no se inventa. Son **posibles rutas originales**, no registros leídos del mando.

El analizador rechaza el resultado si no aparecen ambos controles en la imagen OEM original. La CI comprobó el hash fijado, el rastreo y las pruebas sintéticas.

## Método y falsos positivos

La herramienta `tools/audit_bruce_owner_writers_phase54.py`:

- Comprueba longitud y SHA-256 de la actualización original **`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`**.
- Revalida cada instrucción inicial `LDR` y su **literal PC-relativo exacto**, en vez de confundir la presencia de bytes con un acceso ejecutado.
- Conserva solo valores de registros derivados de constantes originales y sumas/restas simples.
- En llamadas no modeladas elimina los registros *caller-saved*. En `POP/LDM` invalida alias potencialmente sobrescritos.
- Explora ambos lados de condiciones desconocidas, pero **no** afirma la factibilidad de ninguna rama. Detiene la interpretación en predicados `IT` y retornos indirectos no resueltos.
- Distingue destinos positivos conocidos (`owner+0x90`) de los **objetivos** (`owner+4/+8/+12`).

Una lectura `LDR` desde RAM no aporta valores al modelo. No se realiza captura de memoria física.

## Decisión técnica

La búsqueda de los campos `owner+4/+8/+12` sigue **abierta**. Las referencias directas al propietario ya estudiadas no han aportado nuevos escritores; deben investigarse inicializadores a los que llegue el puntero por campos, argumentos indirectos u otras fuentes.

**Lo más útil para la próxima fase** es rastrear *hacia atrás* desde los consumidores de `owner+8` y desde el registro de clase 10, buscando constructores o listas de clases realmente seleccionadas, con un modelo de procedencia de objetos más específico. Si el firmware firmado no permite resolver la selección física, la siguiente evidencia es una **captura pasiva y reversible de enumeración USB**, cuyo resultado debe etiquetarse como evidencia indirecta y **no como un volcado RAM**.

No se ha demostrado clase 10 activa, control arbitrario de callbacks desde el ordenador, firmware propio ejecutable, elusión de **HAB CLOSED** ni compatibilidad Xbox/Switch 2.

## Reproducción

```bash
python -m unittest tests.test_bruce_owner_writers_phase54 -v
python -m tools.audit_bruce_owner_writers_phase54 local/bruce_pvt_a_prod_signed.bin --out local/phase54-writers.json
```

[Registro de evidencia](../../evidence/bruce-owner-writers-phase54.json). [Auditoría CI original firmada](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40344287059).
