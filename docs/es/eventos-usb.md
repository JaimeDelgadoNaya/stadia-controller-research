# Fase 15 — Tabla de eventos USB y límite de transferencia

**Muestra:** bootloader A, build 169429, 131.072 bytes, SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. Se analizó el binario privado **sin conectar el mando**. El archivo original no se publica.

## Hallazgo 1: despacho de 11 eventos internos

La función `0x60809C58` resta uno al identificador de evento, comprueba el rango 0–10 y ejecuta `TBB [PC, R1]` en `0x60809C64`; la tabla ocupa once bytes desde `0x60809C68`. El puntero Thumb `0x60809C59` figura en la tabla de callbacks situada en `0x60816284`.

| Evento interno | Dirección de salto |
|---:|---|
| 1 | `0x60809C74` |
| 2 | `0x60809CCC` |
| 3 | `0x60809CF2` |
| 4 | `0x60809D74` |
| 5 | `0x60809D74` |
| 6 | `0x60809CFA` |
| 7 | `0x60809D22` |
| 8 | `0x60809D74` |
| 9 | `0x60809D48` |
| 10 | `0x60809D54` |
| 11 | `0x60809D68` |

Los eventos 4, 5 y 8 van directamente a la rama predeterminada, que devuelve `1`. Los identificadores fuera de 1–11 también toman esa rama. El hecho de que existan once entradas **no significa que el ordenador pueda enviar once comandos**: esta función atiende **eventos internos** del controlador USB; todavía no se ha reconstruido el despachador de solicitudes de host.

## Hallazgo 2: función de transferencia limitada a 512 bytes

En `0x60809B28`, las instrucciones ejecutan `CMP.W R2, #0x200` y continúan solo si el tamaño no supera 512 bytes. Para un tamaño superior, el código devuelve `3` antes de llamar a las siguientes rutinas. La función también llama indirectamente a un método del objeto y después usa `0x60805694` (interfaz de transferencia). **No se ha demostrado la procedencia externa del argumento R2.**

El límite observado es de **esta rutina**, no una afirmación universal sobre todas las transferencias de la aplicación, del bootloader o del protocolo USB.

## Relación con la fase 14

La otra rutina en `0x60809E64`, referenciada desde `0x60816290`, comprueba eventos mayores de `0x7F` y despacha condicionalmente a un callback en RAM `0x20009168`. El constructor lo inicializa con un handler vacío. **No se ha encontrado todavía una ruta demostrada para sustituirlo ni un enlace con las rutinas de escritura en flash.**

La tabla de once eventos y el callback de eventos mayores de 127 **no son el mismo despachador**; atribuirles códigos de comando o capacidades de programación sin trazar sus llamadores sería incorrecto.

## Código y reproducción

`tools/audit_usb_event_dispatch.py` vuelve a verificar el SHA-256 del binario, siete fragmentos de instrucciones y sus bytes críticos, decodifica la tabla de saltos y produce un JSON sin datos personales. El programa trabaja con un archivo **local**, no accede al mando.

```powershell
py tools/audit_usb_event_dispatch.py local/bootloader-a.bin --out local/fase15.json
py -m unittest discover -s tests -v
```

Las pruebas de GitHub Actions usan datos sintéticos y no requieren firmware propietario.

## Próximo paso

Seguir el recorrido **Bulk OUT `0x07` → recepción efectiva → estructuración de mensajes → dispatch de solicitudes → validaciones → escritura**, comprobando cada enlace en el bootloader real. Hasta disponer de esa traza **no** existe prueba de comandos USB aprovechables, fallo de validación con impacto, ejecución de firmware propio ni elusión de HAB CLOSED.

**Riesgo físico:** cero durante esta fase; no se realizó ninguna operación USB, escritura en flash o fusibles.