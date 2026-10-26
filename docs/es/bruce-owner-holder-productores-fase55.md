# Fase 55 — Procedencia de productor: `owner` se registra como campo de otro objeto

**26/10/2026 — actualización Bruce OEM original firmada**, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Auditoría exclusivamente offline.

## Nuevo hallazgo: el propietario USB se guarda dentro de un objeto diferente

Las fases 51–54 siguieron referencias directas al objeto `owner=0x2000A2A8`, sin localizar los escritores de `owner+4/+8/+12`. La fase 55 cambia de dirección: verifica que un constructor firmado recibe el puntero a `owner` **por R2**, no por R0, y lo almacena en el desplazamiento **+0x80 de su objeto receptor**.

```asm
0x60079D7C  LDR R2,[PC,#0x54]      ; literal 0x60079DD4 = 0x2000A2A8
0x60079D84  BL 0x6007EB8C

0x6007EB96  MOV R4,R0              ; R0 = base de OTRO objeto, desconocida
0x6007EB9E  MOV R8,R2              ; R8 = 0x2000A2A8 (owner)
...
0x6007EBAC  BL 0x601017FC         ; R8/R4 son callee-saved
...
0x6007EBB4  STR.W R8,[R4,#0x80]   ; [objeto_de_R0+0x80] = owner
```

La transferencia de dirección entre los registros está **anclada a 19 instrucciones OEM exactas**, sin inventar resultados de una captura de RAM. Se verificó el valor del literal PC-relativo y el orden de instrucciones frente a la imagen firmada.

**Importante:** el destino es `[R4+0x80]`, no `[owner+0x80]` ni `[owner+8]`. **R4 recibe R0, mientras que owner llega por R2.** No conocemos el valor de R0 ni la dirección absoluta del campo. Tampoco sabemos si este constructor se ejecuta en el dispositivo físico. Así se preserva la distinción que ya descartó el falso positivo de la fase 51.

## Segundo grupo: registros de clase contiguos en la imagen de arranque

Se confirmaron dos *getters* OEM firmados:

| Getter Thumb | Literal | Valor devuelto |
|---|---|---|
| `0x600610FC` | `0x60061100` | `0x200030E8` |
| `0x60061104` | `0x60061108` | `0x200030E8` |

El bloque inicializado y firmado que se copiaría a RAM contiene:

| Dirección RAM de registro | Función OEM | Descriptor | Selector en byte +4 |
|---|---|---|---|
| `0x200030E8` | `0x60061249` | `0x200030A0` | **2** |
| `0x200030F4` | `0x600613FD` | `0x20003100` | **10** |

Ambos registros tienen 12 bytes y están juntos. Esto **demuestra que la actualización OEM contiene un grupo firmado con las clases 2 y 10**, no que la clase 10 pertenezca a la configuración USB activa.

## Grafo de procedencia: relación todavía no demostrada

```text
Literal firmado 0x60079DD4
            │
            ▼
owner = 0x2000A2A8
            │
            └── BL 0x6007EB8C → [OBJETO PADRE DESCONOCIDO + 0x80]
                                           │
                                           ?  consumidores no acreditados
                                           │
[owner + 4] = 0x2000A2AC ◀────────────────┘
            │         ?
            ▼         ?  VÍNCULO NO DEMOSTRADO
registros firmados 0x200030E8 ... 0x200030F4
            └── selector de clase 10 en el segundo registro

[owner + 8] = 0x2000A2B0 → método dinámico: VALOR DESCONOCIDO
[owner +12] = 0x2000A2B4 → recuento: VALOR DESCONOCIDO
```

**No se ha encontrado el productor del método `owner+8` ni del array `owner+4`.** El nuevo enlace hacia un objeto contenedor sugiere dónde buscar indirectamente, pero el puente entre el contenedor y la configuración activa sigue abierto.

## Cómo continuar

La **fase 56** debería localizar el origen del objeto pasado en R0 en `0x60079D84`, y después identificar los consumidores de su campo `+0x80`. Es el modo más específico de comprobar si esa referencia a owner se utiliza para preparar la configuración.

Si el análisis firmado continúa sin resolver los valores dinámicos, preparar una **captura USB de solo lectura**, sin interpretar los descriptores como un volcado de RAM. Ningún paso de esta fase ha demostrado escritura arbitraria de callbacks, ejecución propia, bypass de HAB CLOSED ni funcionamiento nativo Xbox/Switch 2.

## Reproducción y prueba original

```bash
python -m unittest tests.test_bruce_owner_holder_phase55 -v
python -m tools.audit_bruce_owner_holder_phase55 local/bruce_pvt_a_prod_signed.bin --out local/phase55-owner-holder.json
```

El script rechaza hash, longitud, anclas o registros de clase que no coincidan. [Resultado CI con imagen OEM original](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40347175043). [Evidencia](../../evidence/bruce-owner-holder-phase55.json).

**Ninguna petición USB enviada ni lectura de RAM/flash instaladas; ninguna escritura de flash ni eFuses.**
