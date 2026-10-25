# Reorientación tras la fase 29: actualización real, aplicación y criterio de abandono

**Propósito:** determinar si existe una vía **controlable desde el ordenador, autenticada y recuperable** para ejecutar código nuevo en el mando Stadia sin inutilizarlo. No seguir investigando getters y punteros internos sin un nexo demostrado con un protocolo host.

## Resultado actual y tres niveles de evidencia

| Punto de control | Evidencia | Lo que aún falta |
|---|---|---|
| USB normal `18D1:9400` | **Medición física anterior:** WinUSB `bmRequestType=0xA1, bRequest=0x81` devuelve versión, build app 337784, bootloader 169429 | Esa solicitud **es lectura de estado**, no autorización de actualización |
| USB bootloader `18D1:946B` | Descriptores y callbacks Bulk OUT `0x07` / IN `0x87` auditados; callbacks finales iniciales son inertes | Ningún enlace externo verificado hasta un parser y luego un escritor flash |
| USB ROM `1FC9:0135`, cargador firmado RAM `15A2:0073` | Dispositivos medidos en investigación previa; el actualizador oficial archivado utiliza WebUSB y cargadores firmados | Identificar **por código del host** cada transferencia, su estado/método y la autenticación real; no confundir carga de firmware firmado con ejecución arbitraria |
| Imagen Bruce candidata | El archivo privado `bruce_pvt_a_prod_signed(1).bin` de 1.050.984 bytes tiene SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3` | **No** es una extracción íntegra contrastada de la flash de aplicación instalada |
| HAB de ROM | **CLOSED** medido; firmar/validar sigue siendo una condición efectiva | Ningún bypass verificado, ninguna imagen propia arrancada |

**Fuentes públicas del flujo de actualización, para inspección offline y sin flashear:**

- Código y documentación del procedimiento: https://github.com/GaryOderNichts/StadiaController
- Copia local del actualizador web original: https://github.com/hazrpg/stadia-flasher
- Secuencia WebUSB y ficheros de fábrica preservados: https://github.com/merlinschumacher/Stadia-Controller-Bluetooth-Firmware-Bin

Estos recursos documentan una vía **real de actualización firmada desde el host**. No demuestran que acepte firmas ajenas o una modificación no autenticada.

## Primera inspección estática de la aplicación Bruce

Se ha inspeccionado **sin ejecutar** la imagen proporcionada:

- Tamaño: **1.050.984 bytes**.
- SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.
- Primeros vectores: `SP=0x2002B828`, reset Thumb `0x60040501`. Usamos **base XIP inferida `0x60040000`** para traducir desplazamientos; no es prueba de identidad con la aplicación instalada.
- Contiene mensajes referentes a actualización aplicada, bootloader y gestión USB, así como literales vinculados a `usb_device_vendor.cc` y una referencia ASCII a la versión `337784`.
- El literal `0x60058BD8` referencia una cadena de registro de **solicitudes host USB desconocidas**.
- La rutina candidata en **`0x60058B68`** comprueba que el puntero de entrada no sea nulo, compara **el primer byte del búfer con 5** en `0x60058B74`, y si coincide avanza el puntero y llama directamente desde `0x60058B7A` a **`0x60058AA8`**. Otra rama registra la solicitud desconocida.
- **El byte `5` pertenece al contenido del búfer, no está identificado como `bRequest` USB, ni constituye un opcode de actualización confirmado.** No hay enlace comprobado entre el host, esa función y una escritura flash.

Herramienta de reproducción: `tools/audit_signed_app_surface.py` (SHA-locked, solo lectura). Evidencias saneadas en `evidence/application-surface-gate.json`; no se publica el archivo binario.

## Plan de investigación acotado: dos paquetes y una decisión

### Paquete A — Protocolo del host (prioridad máxima)

**Una etapa de investigación offline**, trabajando sobre el código preservado del actualizador y el estado de los dispositivos USB:

1. Extraer la máquina de estados del JS de WebUSB sin ejecutarlo: VID/PID, interfaz, dirección, tipo de control, `bRequest`, `wValue`, `wIndex`, tamaños de transferencia, secuencia y errores.
2. Diferenciar **USB normal**, **USB bootloader**, **ROM SDP** y **cargador firmado en RAM**. Relacionar cada mensaje de host con el receptor real del firmware correspondiente.
3. Seguir del receptor a la validación de longitud, almacenamiento, autenticación HAB y resultado. Marcar cada arista como **verificada**, **inferida** o **sin demostrar**.
4. **Prohibido en la investigación:** enviar paquetes de prueba, cargar firmware propio o modificar la flash del mando. El análisis de un archivo de actualización oficial no equivale a disponer de recuperación garantizada.

**Entrega:** matriz host→modo USB→comando→receptor→validaciones→escritura/autenticación, con direcciones y referencias verificables. Basta una columna sin demostrar para impedir una conclusión de ejecución.

### Paquete B — Aplicación y alternativas de ejecución (solo si A da una pista concreta)

**Una etapa adicional, también offline**:

1. Seguir las referencias USB y actualización en `bruce_pvt_a_prod_signed(1).bin`, incluida la candidata `0x60058B68 → 0x60058AA8`; no interpretar cadenas de log como prueba de recepción externa.
2. Verificar el formato y partición de la imagen, límites de autenticación y posibilidades de arranque con imagen firmada; distinguir arranque de una imagen **Google firmada** de firmware propio.
3. Analizar únicamente rutas recuperables en teoría, documentando las precondiciones que harían falta para afirmar recuperación real. **Bootloader B vacío** no se puede considerar un respaldo operativo.
4. No inferir que la imagen Bruce coincida byte a byte con la instalada por coincidir el nombre/build.

**Entrega:** árbol de decisión sobre actualización autenticada, ejecución de código propio y recuperación, con cada premisa probada o marcada como desconocida.

### Regla de parada obligatoria

**Máximo dos paquetes de investigación desde esta reorientación.** Al terminar:

- **CONTINUAR solo** si hay una secuencia host controlable **demostrada**, recepción local verificada y una ruta de ejecución **autorizable/autenticable y recuperable** con condiciones concretas; no basta una escritura flash interna.
- **PARAR la línea de modificación interna** si faltan esa entrada, la cadena de validación, la posibilidad de ejecución propia o la recuperación fiable, o si la única operación accesible es instalar imágenes firmadas existentes.
- No reiniciar otras 20 fases de búsqueda de `STR` sin nuevos datos de host. No habrá experimentos persistentes sobre el mando sin un medio de recuperación explícitamente demostrado.

## Alternativa definida: puente externo para Xbox

Si la regla de parada se activa, el mando original queda intacto. Arquitectura:

```text
Mando Stadia (BLE HID o USB)
          ↓
   Receptor/puente externo
   (ESP32-S3, PC o similar)
          ↓
   Traducción de botones/ejes
          ↓
   Interfaz compatible/autorizada
          ↓
       Xbox
```

Existe un **proyecto real de puente Stadia BLE → USB Xbox 360/XInput para PC**:
https://github.com/danzig666/stadia-dongle-esp

**Advertencia importante:** emular un dispositivo Xbox 360/XInput para un **PC**
no demuestra compatibilidad con una consola **Xbox One o Xbox Series X|S**. Estas
consolas pueden requerir autenticación/accesorios autorizados; habría que
verificar una solución compatible o un controlador autorizado de paso. No se
prometerá soporte de consola sin prueba documentada.

## Criterio para cerrar

La meta no es agotar todas las posibles escrituras ARM. Es decidir, con un
presupuesto finito de investigación y sin arriesgar el mando, si el firmware
original puede servir para el objetivo o si conviene implementar el puente.

## Resultado del paquete A (realizado)

**[Matriz de mensajes host y validaciones](protocolo-actualizador-webhid.md).** El actualizador archivado utiliza WebHID en ROM SDP y cargador original firmado en RAM. La programación está documentada en el código del host, pero no hay ejecución propia autorizable ni recuperación demostradas. **No** se ha utilizado el mando. El paquete B restante queda acotado a firma/arranque, identidad del firmware firmado y recuperación; tras él se aplicará la regla de parada.

## Decisión obligatoria aplicada — fase 31 (cerrado)

Se completaron ambos paquetes de investigación offline. El [informe de cierre](decision-final-ejecucion.md) verifica dos firmas CMS por cada imagen original, hashes y la cadena de autenticación del bootloader A, junto con HAB CLOSED medido previamente. No se ha demostrado ejecución de imagen propia autenticable; la ranura B está vacía y tampoco existe recuperación completa o rollback probado. **DECISIÓN: PARAR modificación interna y comenzar puente externo reversible.** No retomar barridos indefinidos sin nueva evidencia independiente que cambie simultáneamente ejecución y recuperación. Evidencia saneada: `evidence/phase31-final-auth-recovery.json`.
