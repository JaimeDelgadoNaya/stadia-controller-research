# Fase 93 — Auditoría estática del archivo nxp-sdp-overrun

Fecha: 2026-11-24. Archivo facilitado por el usuario. No se ejecutó el exploit, no se conectó hardware ni se generó un payload.

## Identidad de la copia
- Archivo: nxp-sdp-overrun-main.zip
- SHA-256: fbaae33730aa1fb959843c9531abcc436fa50f04c1d082215e4bae0753521908
- main.py SHA-256: e41e659f25388578ef9b2c1a1800adecf9e290d5ec0b57fbabb8705c3f765404
- Versión declarada: 1.0.0; autor declarado: Thomas Hebb; licencia GPL-3.0-only.
- Origen declarado: https://codeberg.org/tchebb/nxp-sdp-overrun
- El ZIP no contiene metadatos de commit; su correspondencia con el upstream no está autenticada.
- Referencia ROM declarada: RT1060 HAB 4.3.7. La versión de la unidad Stadia sigue sin comprobarse.
- El archivo no contiene una imagen de firmware Zephyr ni una imagen de ROM.

## Hallazgos
El README describe un desbordamiento de memoria en la implementación USB SDP de BootROM, distinto de la vulnerabilidad U-Boot SPL discutida en fase 92. El código fuente declara una modalidad temporal de modificación ROMC y una modalidad irreversible FIELD_RETURN. Ambas requieren validación independiente; la segunda queda excluida del plan de pruebas de este proyecto.
La familia de procesadores coincide, pero las referencias a la ROM son específicas. No puede inferirse compatibilidad de una unidad real por el nombre del procesador.

## Limitación crítica de la comprobación de éxito
En main.py, la rama temporal imprime el mensaje de éxito si el número de bytes que devuelve la escritura USB coincide con la longitud enviada. Eso no constituye una medición independiente del estado HAB ni evidencia de ejecución. No contabilizar ese mensaje como prueba de desbloqueo.

## Validación local efectivamente realizada
Siete comprobaciones estáticas, 7/7 correctas:
1. Integridad CRC ZIP.
2. Sintaxis AST de los tres archivos Python.
3. Versión declarada 1.0.0.
4. Presencia de modalidades temporal y permanente separadas.
5. Advertencia explícita de irreversibilidad.
6. Identificación del criterio de éxito basado exclusivamente en longitud de escritura.
7. Ausencia de archivos de imagen de firmware.
No se importaron ni ejecutaron módulos del proyecto, no se instalaron dependencias y no se reprodujo la vulnerabilidad.

## Puertas de validación para la investigación
- Identificar de forma no destructiva la revisión de silicio y la versión ROM correspondiente, contrastar procedencia.
- Mantener separado el resultado de una transferencia USB de la prueba independiente de ejecución.
- Diferenciar estado temporal, persistencia y compatibilidad del firmware con periféricos de la placa.
- Mantener NO-GO de programación de eFuses, flash y cambios irreversibles en la única unidad.
- Evaluar la arquitectura de firmware y mapeo de botones/ejes por separado, mediante un dispositivo virtual o un puente externo. XInput en PC no implica autenticación con consola Xbox.

Estado: código disponible e inspeccionado; ejecución y compatibilidad específica no verificadas.
