# Objetivo directo: Stadia → USB → Switch 2

[English](../en/direct-switch2.md)

Revisión: **2026-10-25**. El propietario pide modificar el software del propio
mando y conectarlo directamente a Switch 2, **sin adaptadores externos**. Esta
instrucción sustituye la prioridad externa de la fase 31. Se reanuda un análisis
offline acotado del receptor de la aplicación; no hay todavía ejecución propia,
firmware instalable ni prueba de compatibilidad directa.

## Primer destino propuesto

Implementar el perfil **USB del Nintendo Switch Pro Controller original** es
un objetivo más acotado que reproducir el mando Switch 2 Pro completo. Nintendo
documenta expresamente su uso por cable en Switch 2: activar la comunicación por
cable del Pro Controller en Ajustes → Mandos y accesorios y conectarlo al dock.
Eso prueba aceptación del mando original, **no de una emulación Stadia**.
[Procedimiento oficial](https://en-americas-support.nintendo.com/app/answers/detail/a_id/49387/p/989/c/947).

Cambiar VID/PID no basta. La investigación primaria del protocolo original
describe intercambio USB `0x80`/`0x81`: estado `01`, handshake `02`, negociación
`03` y permanencia en USB `04`. La referencia al cambio de baud pertenece a la
electrónica del mando original; una emulación debe reproducir su comportamiento
visible para el host, sin copiar esa arquitectura interna.
[USB-HID-Notes, revisión inmutable](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/USB-HID-Notes.md).

También requiere responder a subcomandos, no solo publicar botones: información
del dispositivo, selección de modo, lectura de datos de calibración y estado de
luces/sensores/vibración según lo que la consola solicite. Las notas identifican
salida `0x01`, respuesta `0x21` y entrada completa `0x30`.
[Informes](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_notes.md),
[subcomandos](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering/blob/b354f21ae81f7b0d1d060b2b61e66ad0d9bc1756/bluetooth_hid_subcommands_notes.md).

## Por qué BLE no es el primer objetivo

La investigación de ndeadly distingue el Bluetooth BR/EDR del mando original y
el BLE de Switch 2. El segundo usa anuncios filtrados por Nintendo, GATT propio,
emparejamiento distinto de SMP y parámetros de conexión particulares. Por tanto
el perfil BLE HID actual de Stadia no es directamente intercambiable. Disponer
de radio BLE no demuestra que su firmware/controlador pueda implementar todos
esos requisitos. [Interfaz BLE, revisión
`a3306b473acff0d6844fb1e288883a3940df0baf`](https://github.com/ndeadly/switch2_controller_research/blob/a3306b473acff0d6844fb1e288883a3940df0baf/bluetooth_interface.md).

## Trabajo acotado y criterios de avance

1. Analizar offline el receptor USB de la aplicación Bruce y los límites de
   ejecución/autenticación. Documentar entradas realmente controlables y su
   recorrido; un desbordamiento aislado o una escritura flash no bastan.
2. Preparar un núcleo de protocolo independiente del hardware, con transcripciones
   sintéticas y pruebas de handshake, subcomandos, informes neutrales y botones.
   Las pruebas offline validan código de protocolo, no su ejecución en Stadia.
3. Continuar al backend USB de Stadia solo al demostrar una vía concreta de
   ejecución propia y recuperación. Debe acceder a entradas físicas y responder
   a transferencias de control e interrupción con temporización adecuada.
4. Primera aceptación física: menú de Switch 2, botones y sticks por cable,
   desconexión/reconexión y estado neutral. Gatillos analógicos se traducirían a
   ZL/ZR digitales; umbral y remapeo deben quedar explícitos. IMU, NFC, audio,
   despertar, vibración y funciones nuevas de Switch 2 quedan fuera del mínimo.

No se ha demostrado aún el requisito del paso 3. El análisis de software puede
avanzar; no corresponde presentar un binario de emulación como instalable.

## Procedencia y reutilización

Las dos revisiones anteriores están clonadas como referencias de solo lectura.
En esos árboles no se encontró un archivo de licencia general en la raíz; ello
no concede permiso para copiar código, documentación o capturas al repositorio
MIT. Esta propuesta resume hechos de protocolo con atribución y no incorpora
código ajeno. Cualquier reutilización posterior debe comprobar la licencia del
archivo concreto; una implementación propia debe conservar la procedencia de
las observaciones y pruebas independientes.
