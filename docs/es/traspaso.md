# Traspaso completo de la investigación

[English](../en/handoff.md)

Estado al 25 de octubre de 2026. Este documento permite continuar el trabajo sin
necesitar el historial del chat. No hay firmware propio instalable ni una vía
demostrada de ejecución de código propio.

## Objetivo original

Investigar si el mando Stadia puede ejecutar firmware propio conservando su
electrónica, con la aspiración de mejorar compatibilidad entre plataformas.
La compatibilidad directa con una consola Xbox requiere resolver además su
autenticación; no se ha implementado esa parte ni un protocolo nuevo.

## Estado comprobado

| Elemento | Resultado | Tipo de evidencia |
|---|---|---|
| Firmware instalado | Bruce 337784 (`0x52778`) | Lectura USB real |
| Bootloader A | 169429 (`0x295D5`), extraído | Lectura real y firmas CMS verificadas |
| Bootloader B | 128 KiB completamente `0xFF` | Lectura real y relecturas |
| MCU | ID `0x006C0000`, etiqueta 106XA0 | Lectura real |
| Flash | ID `0x17C8`, GigaDevice 16 MB | Lectura real |
| HAB | CLOSED, ROM `0x12343412`; propiedad 0x11 = 1 | Dos rutas de consulta reales |
| Estado final tras pruebas físicas | USB normal, misma respuesta de versión | Lectura real posterior al reinicio |
| Comprobación de rangos de imagen | Acepta un rango desbordado y cierto tamaño cero | Emulación de instrucciones originales |
| Comprobación de almacenamiento | Puede delegar fuera de partición con offset sintético | Emulación, dispositivo físico simulado |
| Ejecución propia / elusión de firmas | No demostrada | Pendiente |

Las mediciones corresponden a una unidad. La aplicación instalada no se extrajo
completa; conocer su build no equivale a verificar el hash de toda su flash.

## Qué se hizo con el mando

Se usó WinUSB ya instalado para leer la versión, y HID para diagnóstico. El
propietario realizó las combinaciones físicas hasta pasar de `18D1:9400` a
`18D1:946B` y `1FC9:0135`. Se consultó primero ERROR_STATUS de la ROM. Después
se cargó el cargador original firmado de Google exclusivamente en RAM, se
consultaron HAB y MCU y se leyó flash mediante FlexSPI con LUT temporal de lectura.

Hubo escrituras temporales en RAM/SRAM y registros FlexSPI. No se enviaron
comandos de programación de firmware, borrado de flash ni programación de
fusibles. Se extrajeron dos regiones de 128 KiB; A contiene el bootloader y B está
borrada. Se reinició por el comando del cargador y se comprobó el regreso a modo
normal con los mismos ocho bytes de versión. Las fases 9, 10 y 11 fueron offline.

## Documentos técnicos y orden recomendado

1. [Mediciones](mediciones.md): protocolos, respuestas, extracción y límites.
2. [Fase 9](arranque.md): validación de aplicación, HAB y bandera estructural.
3. [Fase 10](actualizacion.md): callback, buffers IVT y restauración.
4. [Fase 11](almacenamiento.md): descriptor 0x12, métodos y delegación emulada.
5. [Manifiesto](../../evidence/manifest.json): archivos, hashes y alcance.

## Mapa mínimo para retomar el código

Todas estas direcciones pertenecen al bootloader A build 169429 con SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.

| Dirección | Descripción de investigación |
|---|---|
| `0x60801DD4` | Flujo de actualización/selección de IVT |
| `0x60801EF0` | Salto a aplicación después de validar |
| `0x60801F5C` | Envoltorio HAB entry/authenticate_image_no_dcd/exit |
| `0x60801FE6` | Comprobación de rango de imagen; suma de 32 bits |
| `0x6080200C` | Validador de aplicación |
| `0x608020A8` | Validador de bootloader con bandera estructural/autenticada |
| `0x608022FC` | Callback de alimentación y entrada física |
| `0x6080285C` | Salto Thumb hacia ese callback |
| `0x6080AA66` | Traducción de offset de partición a offset de flash |
| `0x6080AA7C` | Comprobación offset + longitud frente a capacidad |
| `0x6080B0F0` | Escritor de partición sin cifrado |
| `0x60815300` | Tabla de métodos sin cifrado |
| `0x60815320` | Tabla del dispositivo físico |
| `0x60001000` | IVT compartido: descriptor 0x12, 4096 bytes |

Los nombres son descripciones inferidas, no símbolos originales recuperados.
`evidence/bootloader-analysis.json` conserva instrucciones, bytes, llamadas
directas, literales y tablas seleccionadas. Su decodificación usa Thumb M-class.

## Reproducción desde un clon limpio

```sh
python -m venv .venv
# Activa .venv con el comando de tu sistema.
python -m pip install -r requirements-emulation.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
python tools/emulate_range_check.py
python tools/emulate_storage.py
```

Las pruebas y ambos emuladores pueden ejecutarse con la evidencia pública,
sin mando ni binario completo. La suite completa contiene 14 pruebas. El primer
emulador verifica ocho casos de la función de rangos. El segundo verifica cuatro
invocaciones del escritor con contexto construido; intercepta el backend físico
y devuelve éxito simulado. No valida la aceptación final de la flash real.

Para analizar y verificar una extracción propia coincidente:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

El alias representa el IVT compartido mediante los primeros 4096 bytes del
archivo. La verificación comprueba hashes y firmas con certificados incluidos;
no compara por separado las claves con los fusibles SRK. Las regiones extraídas
no son una copia completa de recuperación de los 16 MB.

## Hipótesis que no deben convertirse en conclusiones

- CLOSED está medido: no asumir que cargar datos en RAM permite ejecutarlos.
- El cargador firmado de Google sí se ejecutó; no fue código propio.
- Una imagen llamada dev no implica desbloqueo: las imágenes Bruce comparadas
  comparten el contenido anterior al área final de firmas.
- B vacío es el espacio de bootloader B; no se midió el contenido de aplicación B.
- Existe restauración del IVT, pero no se demostró recuperación ante pérdida de alimentación.
- Los ejemplos de desbordamiento son reales en emulación, pero no hay una entrada
  externa demostrada que permita controlar esos parámetros en la ruta revisada.
- El escritor IVT revisado recibe offset cero y tamaño fijo 4096. Escribir fuera
  de una partición no demuestra elusión de HAB ni ejecución de código.

## Siguiente trabajo útil

1. Seguir llamadores del escritor `0x6080B0F0` y sus interfaces hasta encontrar
   qué parámetros, si alguno, pueden provenir de USB u otra entrada controlable.
2. Separar esa accesibilidad de los efectos: comprobar validaciones posteriores,
   alineación, destinos permitidos y autenticación antes de atribuir impacto.
3. Reconstruir selección de aplicación A/B y sus metadatos de intentos de arranque.
4. Solo proponer otra prueba física si hay una hipótesis concreta y recuperable.
   No se necesita flashear una imagen modificada para reproducir lo publicado.

## Material que permanece local

El repositorio público contiene herramientas, hashes y fragmentos de evidencia,
pero no imágenes propietarias completas ni identificadores personales. En el
espacio de trabajo original se conservan `outputs/bootloader-a.bin`,
`outputs/bootloader-b.bin`, el informe y ZIP de fase 8 y los scripts de extracción
en `work/`. El ZIP es un archivo local, no un release público. El propietario
puede proporcionar esos archivos a su siguiente entorno si desea repetir el
análisis del binario completo. No hay ningún proceso de extracción dejado activo.
