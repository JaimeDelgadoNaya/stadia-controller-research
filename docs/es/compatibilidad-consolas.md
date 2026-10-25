# Fase 32 — Rutas externas para consolas

[English](../en/console-compatibility.md)

Consulta de fuentes oficiales: **25 de octubre de 2026**. Objetivo del propietario:
usar Stadia en las consolas que resulte posible, preservando su firmware.
**Ninguna combinación de adaptador y consola de esta tabla se ha probado localmente.**
Son candidatos documentados por el fabricante; no una certificación del proyecto.

## Matriz de candidatos

| Consola destino | Ruta candidata | Evidencia y condición |
|---|---|---|
| Nintendo Switch | Stadia por USB → MAYFLASH MAGIC-NS 2 → consola | La ficha incluye Switch y la actualización **M:V1.19 / S:V1.30** incorpora Stadia. En modo Switch Pro activar comunicación por cable del mando Pro. [Ficha](https://mayflash.com/product/showproduct.php?id=45), [alta de Stadia](https://www.mayflash.com/Support/showdownload.php?id=203). |
| PS3 | Stadia por USB → MAGIC-NS 2, MAGIC-S PRO 2 o MAGIC-X | Las fichas incluyen PS3; seleccionar el modo de salida correspondiente. Las notas Stadia enlazadas respaldan la entrada. No extrapolar a PS2 o PS1. |
| PS4 | Stadia por USB → MAYFLASH MAGIC-S PRO 2 → consola | Stadia añadido en **M:V1.12 / S:V1.30** y PS4 figura como destino. [Ficha y firmware](https://www.mayflash.com/Support/showdownload.php?id=207). |
| Xbox One / Series X\|S | Stadia por USB → MAYFLASH MAGIC-X → consola | Xbox figura como destino; Stadia añadido en **M:V1.07 / S:V1.30**. Es una afirmación del proveedor, pendiente de validar en la consola y su versión de sistema. [Ficha y firmware](https://www.mayflash.com/Support/showdownload.php?lang=en&id=208). |
| PS5 | Stadia → MAGIC-S Ultimate, investigación limitada | Stadia añadido en **M:V1.05 / S:V1.30**; beta **M:V1.06 / S:V1.31** anuncia PS5 principalmente para juegos de lucha. La conjunción es una **hipótesis de compatibilidad**, no una prueba Stadia+PS5. No promete todo el catálogo. [Ficha](https://www.mayflash.com/product/showproduct.php?id=49), [alta de Stadia](https://www.mayflash.com/Support/showdownload.php?id=206). |
| Switch 2 | Candidato adicional de MAYFLASH | Las fichas actuales de MAGIC-NS 2 y MAGIC-X anuncian Switch 2. Combinación Stadia+Switch 2 y versión de firmware concreta todavía sin verificar en el proyecto. |
| Otras consolas | Sin ruta establecida en esta fase | No se investigó exhaustivamente cada generación; no confundir ausencia de evidencia con imposibilidad. |

Las versiones indicadas son las que **introdujeron** Stadia; no se presentan
como las últimas disponibles. Actualizar exclusivamente el adaptador correcto
según su modelo y revisión, siguiendo el manual del fabricante.

## Cable primero; Bluetooth pendiente

Las notas oficiales de Stadia mencionan volver a enchufarlo al adaptador tras
desconexión o varios minutos sin uso por cable. Esa es la base de la primera
prueba. Las listas generales de mandos Bluetooth no especifican claramente Stadia:
no damos por verificado su enlace BLE en estos modelos ni prometemos vibración,
audio o botones especiales por asociar capacidades generales del adaptador.

No encontramos soporte Stadia explícito en las fuentes consultadas de
[8BitDo USB Adapter 2](https://shop.8bitdo.com/products/8bitdo-usb-adapter-2) o
[descargas Brook](https://www.brookaccessory.com/dl.php). No son alternativas
validadas por esta investigación. El puente ESP32-S3 preparado en esta fase
documenta salida Xbox 360 para PC; encadenarlo a otro adaptador requiere una prueba
independiente y no añade compatibilidad con consolas por sí solo.

## Próxima prueba física útil

Elegir una consola y un adaptador que estén realmente disponibles. Registrar
modelo/revisión, firmware del adaptador, versión del sistema, juego y cable.
Conectar Stadia al adaptador por USB y comprobar menú, cruceta, botones, dos
sticks, gatillos, guía/inicio, desconexión y reconexión. Después comprobar
vibración y funciones adicionales por separado. Repetir tras reposo y registrar
avisos del sistema. Solo marcar como probado el conjunto exacto observado.

Para Xbox debe comprobarse también aceptación continuada del accesorio; el
fabricante lo anuncia compatible, pero esta investigación no establece su
autorización ni garantiza que futuras versiones del sistema lo admitan.
[Soporte Xbox sobre el error 0x82d60002](https://support.xbox.com/en-US/help/errors/error-code-0x82d60002)
es una referencia de diagnóstico; el contenido requiere JavaScript y no se
extrajo en esta revisión. No se instaló ni compró ningún adaptador.

## Estado de acceso a las fuentes

Las notas Stadia se recuperaron directamente de los enlaces oficiales `id=203`,
`id=207` e `id=208`; las fichas NS 2 y Ultimate por `showproduct.php?id=45/49`.
Las fichas nominales MAGIC-X y MAGIC-S PRO 2 devuelven 404 al abrirlas en esta
revisión, aunque el buscador conserva su contenido oficial con Xbox One/Series
y PS4 como destinos, respectivamente. Por ello los enlaces de la tabla apuntan
a las notas recuperables, y los destinos de esos dos modelos se consideran
**información oficial indexada pendiente de reconfirmación directa**.
