# Próximos pasos y niveles de evidencia

[English](../en/roadmap.md)

**Medido:** respuestas del mando, contenido de regiones y versión final en modo normal.
**Verificado sin conexión:** hashes de bloques firmados y firmas CMS con claves incluidas.
**Inferido estáticamente:** flujo de control seleccionado y correspondencia RVT para el hash registrado.
**Cuestión abierta:** alcance de la observación aritmética, callbacks y ejecución alternativa.

Tareas concretas siguientes:

1. Reconstruir los callbacks indirectos entre `0x60801E36` y `0x60801E66`, sus
   restricciones de destino y el comportamiento de error y recuperación.
2. Seguir los tamaños boot-data hasta la comprobación de rangos y las llamadas
   HAB posteriores. Determinar si un rango malformado puede tener efectos después
   de la validación criptográfica.
3. Reconstruir selección de aplicación A/B, metadatos de intentos de arranque y
   respaldo. Que el bootloader B esté vacío no demuestra que la aplicación B lo esté.
4. Mapear el despacho USB normal y del bootloader y las interfaces de diagnóstico
   realmente disponibles en hardware de producción.
5. Identificar una vía concreta y recuperable de ejecución antes de implementar
   otro protocolo USB/Bluetooth. La compatibilidad con una consola Xbox es otro
   problema y no está implementada.

El repositorio no contiene una auditoría completa de ROM, una copia integral del
dispositivo, un exploit ni firmware propio. Las herramientas iniciales trabajan
deliberadamente con archivos locales.
