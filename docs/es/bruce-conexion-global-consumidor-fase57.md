# Fase 57 — Puente firmado entre el objeto dinámico y un consumidor de `owner+0x80`

**26/10/2026.** Análisis sin hardware de la actualización Bruce OEM original: SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. La cadena de instrucciones que sigue es **condicional y estática**. No hay lectura real de RAM ni prueba de ejecución en el mando.

## Hallazgo nuevo: productor y consumidor usan el mismo registro global

La fase 56 determinó que `0x60079D76` solicita 164 bytes a una cadena de asignación ITCM, que conserva el retorno en R4. La fase 55 verificó el constructor `0x6007EB8C` y la escritura de `owner=0x2000A2A8` en `[R4+0x80]`.

Ahora se han enlazado por código OEM original dos accesos al **mismo registro SRAM `0x2001EE30`**:

```text
0x60079D76 BL 0x6013D378  (164 bytes)
        ↓
0x60079D7E MOV R4,R0       (guarda retorno de asignación)
        ↓
0x60079D84 BL 0x6007EB8C  (constructor; [objeto+0x80] = owner)
        ↓
0x60079D9A BL 0x6007E784  (operación sobre objeto+0x0c, NO lector +0x80)
        ↓ si se toma la rama 0x60079DA2 BEQ
0x60079DBA MOV R1,R4
0x60079DBC LDR R0,[PC,#0x24]  ; literal en 0x60079DE4 = 0x2001EE30
0x60079DBE BL 0x60079C6C
        ↓
0x60079C78 STR R1,[SP]
0x60079CD2 LDR R3,[SP]
0x60079CD8 STR R3,[R6]       ; R6 = dirección global recibida en R0
        ↓
[0x2001EE30] = puntero del objeto (ruta condicional)
        │
        ▼
0x60079C50 LDR R1,[PC,#0x14]  ; literal en 0x60079C68 = 0x2001EE30
0x60079C52 LDR R3,[R1],#4    ; lee 1ª palabra global
0x60079C5A STR R3,[R0],#4    ; copia al búfer del llamador
        ↓
0x60074D94 BL 0x60079C50   (pasa búfer local SP)
0x60074DA4 LDR R0,[SP]
0x60074DAA BL 0x6007E794   (función lectora de +0x80)
```

Se han validado las instrucciones originales y la **igualdad literal exacta** de las dos direcciones RAM (escritor y lector). No se infiere que `[0x2001EE30]` contenga ese puntero *en el momento de una medición física*, ni que la rama de inicialización y el lector se ejecuten en un orden determinado. Sobrescrituras concurrentes o fallos de inicialización no están descartados.

## Lecturas condicionales del campo +0x80

La función `0x6007E794` toma un objeto mediante R0, guarda su dirección en R4 en `0x6007E79A` y contiene dos caminos firmados:

| Condición en el código | Lectura | Procedencia local |
|---|---|---|
| `0x6007E7A2 CMP R3,#2`, `0x6007E7A4 BEQ` | `0x6007E7EA LDR.W R0,[R0,#0x80]` | R0 de entrada, intacto en ese salto directo |
| `0x6007E7AA CMP R5,#2`, `0x6007E7AC BEQ` | `0x6007E810 LDR.W R0,[R4,#0x80]` | R4 copiado del R0 de entrada |

**Consecuencia:** tenemos **una ruta posible de lectura del campo +0x80 del objeto publicado en el global**, cuya fuente en el constructor es el puntero a owner. Las rutinas cercanas pasan los valores recuperados a `0x600D54B8`; su efecto completo y factibilidad física todavía requieren auditoría.

## Una segunda función y su veneer ITCM (enlace de instancia pendiente)

La función `0x6007E8AC` contiene `0x6007E8B8 MOV R4,R0` y `0x6007E9A4 LDR.W R0,[R4,#0x80]`. Encontramos el veneer:

- Archivo OEM `0xBFE4` → ITCM ejecutable `0xB7C8`: `LDR.W PC,[PC,#-0]`.
- Literal en archivo `0xBFE8`: `0x6007E8AD`.
- En ITCM `0xAA20 MOV R0,R4`, `0xAA22 BL 0xB7C8`.

Esto acredita el enlace de **código firmado ITCM → rutina de XIP `0x6007E8AC`**, pero **no** que ese R4 sea la misma instancia publicada en `0x2001EE30`.

## Diferenciar dos funciones próximas

`0x6007E784` — a la que llama el constructor — **no es** un lector de `+0x80`. Su código prepara `R0+0x0C`, `R2=0x1B`, y salta a `0x6010177A`. La función de lectura es **otra entrada**, `0x6007E794`, invocada en `0x60074DAA`.

La similitud de direcciones ya no se trata como una llamada directa ni como prueba de identidad. Los datos estáticos mejoran la procedencia, pero no sustituyen la captura real de RAM.

## Balance y siguiente fase

- **Confirmado por bytes originales firmados:** productor R4 → global `0x2001EE30` y getter del mismo global → llamada `0x6007E794`; lectura condicional +0x80 del argumento.
- **No demostrado:** contenido real actual del global, ejecución de las ramas, que el global no se sobrescriba, clase 10 activa, escritores `owner+4/+8/+12`, control de punteros por USB, ejecución propia o bypass de HAB CLOSED.
- **Fase 58 recomendada:** analizar qué hace `0x600D54B8` con el puntero recuperado desde el campo `+0x80` y comprobar si esa función construye o registra una configuración USB real. Complementar con enumeración USB pasiva si sigue faltando evidencia dinámica.

## Reproducir

```bash
python -m unittest tests.test_bruce_parent_consumer_phase57 -v
python -m tools.audit_bruce_parent_consumer_phase57 local/bruce_pvt_a_prod_signed.bin --out local/phase57-parent-consumers.json
```

[Pruebas en CI sobre imagen OEM original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40361129985) · [Registro estructurado](../../evidence/bruce-parent-consumer-phase57.json). Ninguna solicitud USB, lectura RAM física, escritura flash o eFuse.
