# Fase 21 — Procedencia del objeto global RAM y cadena de alias al constructor

**Muestra:** Stadia bootloader A, build 169429, tamaño **131.072 bytes**,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
La investigación se hizo **offline**, con el archivo privado del propietario;
**no** se ha accedido al mando ni publicado su binario.

## Nuevo resultado: 21 literales y 29 cargas candidatas

En la imagen existen **21 palabras de 32 bits alineadas** que contienen
`0x20008B78`, dirección base de la estructura global RAM. Buscando
codificaciones de carga **PC-relativa de Thumb16 y Thumb32** en
`0x60801000..0x60814F00` (final exclusivo), encontramos
**29 posibles instrucciones** que apuntan a esas palabras.

Esto identifica **orígenes del puntero** a distintas partes del firmware.
No demuestra que las 29 instrucciones se ejecuten: el análisis estático
de medias palabras puede decodificar datos como código y no constituye un
grafo completo de flujo de control.

## Cadena de alias concreta, verificada con instrucciones y literales

| Paso | Dirección | Comportamiento |
|---|---|---|
| 1 | `0x6080C0B2` | `LDR R0,[PC,#8]`: carga el literal `0x6080C0BC` |
| 2 | `0x6080C0BC` | Contiene `0x20008B78`, puntero a la estructura global |
| 3 | `0x6080C0B4` | `BL 0x6080BAC0`: entrega `R0` al constructor |
| 4 | `0x6080BAC4` | `MOV R4,R0`: el constructor conserva el alias |
| 5 | `0x6080BB50` | `STR.W R3,[R4,#0x5F8]`: inicializa callback IN |
| 6 | `0x6080BB5A` | `STR.W R3,[R4,#0x600]`: inicializa callback OUT |
| 7 | `0x6080BB6C/70` | Inicializa contextos IN/OUT desde `R5=0` |

Los campos resultantes son `0x20009170` (IN), `0x20009178` (OUT),
y sus contextos en `0x20009174` y `0x2000917C`.
La llamada `BL` se decodifica a partir de los bytes originales
(no se presupone su destino a partir de una etiqueta).

**Este recorrido verifica un alias hacia las inicializaciones que ya
conocíamos, no un registro posterior del callback**. Su ejecución
efectiva en un estado concreto del mando tampoco se ha medido.

## Dos ejemplos de lectores del mismo objeto

- `0x60809E6A` carga el puntero global y el código siguiente
  **lee** los campos `+0x5F0` y `+0x5F4`: callback/contexto del
  despachador de eventos del fabricante, distinto del callback Bulk OUT.
- `0x60809EB8` carga el mismo puntero y **lee** un byte en
  `+0x6C4`, utilizado en la inicialización de endpoints.

Las 29 referencias candidatas exigen revisión por función; no se les
atribuye automáticamente acceso a los cuatro campos de fase 19.

## Límites

El auditor comprueba dos familias de `LDR` PC-relativo; no reconstruye
todas las operaciones `MOV`, `ADD`, aritmética de punteros, escrituras
indirectas, saltos por tablas, DMA, ni llamadas desde otros binarios.
El censo tampoco demuestra que todos esos posibles usos sean alcanzables.
No hemos localizado todavía un **setter posterior** ni seguido el paquete
Bulk OUT del host hasta un analizador de órdenes o una escritura flash.

**HAB CLOSED no se ha eludido; tampoco se ha ejecutado firmware propio.**

## Reproducir sin hardware

`tools/audit_global_alias_sources.py` exige el hash completo de la
imagen y verifica las instrucciones de la cadena de alias. Publica
solo direcciones y datos técnicos; CI usa muestras sintéticas.

```powershell
py tools/audit_global_alias_sources.py local/bootloader-a.bin --out local/fase21.json
py -m unittest discover -s tests -v
```

## Próxima hipótesis (fase 22)

Revisar por función las **29 fuentes de puntero**, seguir sus usos
`MOV/ADD/LDR/STR` mediante un grafo de flujo de datos con límites
explícitos, y separar los usos de lectura de cualquier posible
escritura sobre el objeto del fabricante. Si existe un setter,
identificar además el origen de su invocación y las validaciones previas.
