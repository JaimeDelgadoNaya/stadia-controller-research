# Próximos pasos y niveles de evidencia

[English](../en/roadmap.md)

**Medido:** respuestas del mando, contenido de regiones y versión final en modo normal.
**Verificado sin conexión:** hashes de bloques firmados y firmas CMS con claves incluidas.
**Inferido estáticamente:** flujo de control seleccionado y correspondencia RVT para el hash registrado.
**Emulado:** la función de rangos aislada coincide con su modelo aritmético en ocho casos.
**Cuestión abierta:** alcance de la observación aritmética, callbacks y ejecución alternativa.

Tareas concretas siguientes:

1. Seguir parámetros controlables externamente hasta los métodos de almacenamiento.
   La fase 11 sitúa el descriptor `0x12` en el IVT compartido de 4096 bytes y emula
   el escritor con backend físico simulado. Faltan accesibilidad de entradas y
   aceptación real de parámetros malformados.
2. Seguir los tamaños boot-data hasta la comprobación de rangos y las llamadas
   HAB posteriores. Determinar si un rango malformado puede tener efectos después
   de la validación criptográfica.
3. Reconstruir selección de aplicación A/B, metadatos de intentos de arranque y
   respaldo. La [fase 12](seleccion-aplicacion.md) documenta los selectores 2/3 y
   las marcas de fallo; falta identificar el llamador y cualquier recuperación. Que el bootloader B esté vacío no demuestra que la aplicación B lo esté.
4. Mapear el despacho USB normal y del bootloader y las interfaces de diagnóstico
   realmente disponibles en hardware de producción.
5. Identificar una vía concreta y recuperable de ejecución antes de implementar
   otro protocolo USB/Bluetooth. La compatibilidad con una consola Xbox es otro
   problema y no está implementada.

El repositorio no contiene una auditoría completa de ROM, una copia integral del
dispositivo, un exploit ni firmware propio. Las herramientas iniciales trabajan
deliberadamente con archivos locales.

## Cambio de prioridad tras fase 29 (decisión acotada)

La hoja original de tareas sigue describiendo posibles pistas, pero la **prioridad operativa ahora es [la puerta de decisión sobre actualización real](puerta-decision-actualizacion.md)**: dos paquetes offline como máximo — protocolo WebUSB del host hasta el receptor y, solo si procede, aplicación Bruce firmada y ejecución recuperable — seguidos de decisión **continuar/parar**. No se abrirán más fases de búsqueda genérica de punteros. Si no existe una entrada controlable y una vía de ejecución propia recuperable verificadas, la alternativa será puente externo para Xbox (separando XInput para PC de autenticación de consola).

## Prioridad histórica tras fase 32 (sustituida más abajo)

La parada de la fase 31 sustituye las hipótesis internas históricas anteriores.
Continuar por [compatibilidad con consolas](compatibilidad-consolas.md), elegir
una combinación documentada y probarla físicamente. La
[preparación del puente](puente-externo.md) queda para el prototipo PC ESP32-S3;
su salida Xbox 360 no demuestra autenticación de consola.

## Prioridad vigente: software interno y Switch 2 directa

La instrucción posterior del propietario descarta dispositivos externos y
sustituye la prioridad de puente anterior. Ver [el objetivo directo](switch2-directa.md)
y [la corrección del receptor de aplicación](funcion-mensaje-aplicacion.md).
Se autoriza investigación offline acotada; firmas, ejecución propia y recuperación
siguen siendo bloqueos técnicos. No se ha modificado firmware en esta revisión.
