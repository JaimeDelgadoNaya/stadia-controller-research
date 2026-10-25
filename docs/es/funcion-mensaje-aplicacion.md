# Revisión acotada del mensaje de aplicación

25 de octubre de 2026. El propietario pide modificar el software del Stadia sin
adaptadores, incluyendo conexión directa a Switch 2. Se reabre una revisión
offline acotada; los bloqueos técnicos de firma y recuperación siguen abiertos.

Se ha localizado la muestra Bruce privada y comprobado su SHA-256
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.
Es una imagen firmada de actualización, no una copia completa certificada de la
aplicación instalada. La reverificación de autenticación acepta los originales
y rechaza copias temporales con un byte modificado. No se ha enviado nada al mando.

## Qué hace la pista revisada

La función empieza en `0x60058B64`, antes de la ventana publicada que comenzaba
en `0x60058B68`. Resta uno a la longitud recibida y comprueba el intervalo antes
de despachar la etiqueta. Para etiqueta 5, `0x60058AA8` exige al menos cuatro
bytes de payload, decodifica dos valores de 16 bits little-endian, los guarda en
RAM `0x2001A430` y `+2`, y publica el evento 6. El literal de componente cercano
es `hid_input_target.cc`. El inicializador referencia `HidRumbleTimer` y
registra el consumidor de los dos valores. La longitud total admitida por la
entrada es 1..255; la etiqueta 5 necesita al menos cinco bytes totales.

Esto respalda una interpretación de control HID de dos canales, posiblemente
vibración. No demuestra un receptor de actualización, escritura RAM arbitraria,
ejecución propia ni bypass de arranque seguro. La referencia a un callback no
prueba por sí sola que un host USB pueda alcanzar esa ruta.

```sh
python tools/audit_app_message_role.py local/bruce_pvt_a_prod_signed.bin
python -m unittest discover -s tests -v
```

[Evidencia saneada](../../evidence/application-message-role.json) y
[objetivo Switch 2 directo](switch2-directa.md). El análisis no necesita enviar
órdenes de salida, reiniciar, cambiar drivers ni programar flash.

## Búsqueda de vías independientes

[stadiatool](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/README.md)
documenta flasheo de imágenes firmadas. Los forks públicos revisados no aportaron
ejecución unsigned reproducible. El [anuncio WIP de bitnullbyte](https://www.reddit.com/r/Stadia/comments/1vm7mp6/wip_we_have_honestly_never_been_closer_to_a/)
describe restauración Wi-Fi oficial y aprovisionamiento; modificar URLs aparece
como trabajo futuro. No se encontró allí una imagen modificada con procedimiento
reproducible de ejecución. No se concluye que una vía no publicada sea imposible.

La siguiente pista útil debe unir una entrada controlable con su receptor y un
efecto ejecutable comprobable. La recuperación sigue siendo otro requisito
pendiente. Cambiar nombre, VID/PID o escribir un emulador de protocolo no resuelve
por sí mismo cómo ejecutarlo en Stadia.
