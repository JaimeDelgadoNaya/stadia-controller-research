# Fase 105 — Nueva ruta de arranque seguro: nxp-sdp-overrun y FIELD_RETURN (solo investigación)

**Fecha:** 22 de noviembre de 2026. **Objetivo:** identificar una ruta con posibilidad real de ejecución permanente de código propio en un mando Stadia comercial, sin presentar un exploit publicado como método seguro o ya reproducido.

## Hallazgo determinante: informe comunitario de ejecución y persistencia

En una conversación de r/Stadia iniciada el **14/11/2026**, el investigador **tchebb** publicó un enlace a su proyecto [nxp-sdp-overrun](https://codeberg.org/tchebb/nxp-sdp-overrun). Atribuye a un fallo en el entorno NXP SDP la posibilidad de ejecutar código en el mando y afirma haber desarrollado firmware personalizado sobre Zephyr que aún no está listo para publicar. En ese momento dijo que pretendía añadir un mecanismo de desbloqueo permanente con **FIELD_RETURN**; esto no certifica que esa funcionalidad se haya publicado ni sea segura.

El **16/11/2026**, otro participante de ese hilo afirmó haber activado **FIELD_RETURN** y conseguido arrancar un firmware personalizado mínimo **tras apagar y volver a encender** el mando. En el mensaje principal también anunció experimentos de modo Xbox Series X por Bluetooth y cable. Ambos son testimonios **de terceros**, no pruebas repetidas o revisadas independientemente por nosotros.

**Fuente:** https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/

## Lo que cambia respecto a las fases 95 y 103

Anteriormente teníamos un firmware original firmado y herramientas para la ROM SDP, pero ningún medio comprobado para ejecutar una imagen no firmada con HAB CLOSED. El exploit publicado es un **nuevo candidato de ejecución temporal en RAM**. El testimonio sobre FIELD_RETURN es un **indicio de instalación persistente**, no garantía de recuperación segura.

La documentación técnica de **i.MX RT1060** distingue estados de seguridad Open/Closed/Field Return: con CLOSED, HAB aborta el arranque ante errores de autenticación; los modos Open y Field Return tienen objetivos de desarrollo/servicio. El estado de **esta unidad concreta** sigue sin medirse y hay que distinguir la política ROM, la autorización del bootloader Google y la escritura física a la NOR.

Fuentes:
- NXP i.MX RT1060 Reference Manual, capítulo 9.3.6 sobre modos de seguridad: https://www.pjrc.com/teensy/IMXRT1060RM_rev2.pdf
- NXP MCUXpresso Secure Provisioning Tool: https://docs.mcuxpresso.nxp.com/secure/latest/06_processor_specific_workflow.html
- NXP Field Return dependency on OCOTP (advertencia: el alcance y las variantes de SoC se deben validar, no extrapolar de otros modelos): https://community.nxp.com/t5/i-MX-Security/Field-Return-dependency-on-OCOTP-Module-clock-in-MPU-and-MCU/ta-p/1123766

**No confundir** con la vulnerabilidad SDP de U-Boot SPL publicada también en noviembre de 2026: afecta a un componente SPL de U-Boot que **no se ha identificado en el firmware Stadia**. Su existencia no demuestra aplicabilidad del exploit de tchebb al RT1061.

## Clasificación de rutas

| Ruta | Evidencia disponible | Riesgo / decisión |
|---|---|---|
| Exploit nxp-sdp-overrun en RAM | Publicación del autor + afirmaciones de trabajo sobre Stadia | **Prioridad 1: auditoría de código y prueba únicamente no destructiva** |
| Arrancar código mínimo temporal sin tocar NOR/fusibles | Posibilidad declarada, pero sin reproducción por nosotros | Requisito previo para tocar almacenamiento; no implementado aquí |
| FIELD_RETURN para desactivar el bloqueo permanente | Testimonio de 16/11/2026 de persistencia | **NO-GO en el mando del usuario** hasta verificar revisión, riesgo, efectos en firmas y recuperación; OTP puede ser irreversible |
| Parchear bootloader CDC | Diferencias de 72 bytes, CSF eliminado, advertencia de brick del autor | **NO FLASH** |
| Escribir imagen Xbox nueva directamente | Codec y transporte ARM parcialmente listos, sin firmware para placa | No arrancaría con HAB CLOSED sin ruta de autorización |
| Placa de desarrollo RT1060 | Código portable compilado; no prueba de USB físico | Ruta paralela, recuperable, sin riesgo para el mando Stadia |

## Qué falta para dar el salto a hardware

1. **Obtener y auditar el código de nxp-sdp-overrun.** En la revisión del 22/11/2026 el enlace público fue localizado, pero **Codeberg no se pudo descargar en nuestro entorno**. No se ha inspeccionado ni ejecutado su payload, no se conocen versiones, límites de memoria, comprobaciones de variantes o compatibilidad probada. Este impedimento limita cualquier recomendación de uso.
2. **Reconciliar versiones/revisiones:** el dispatcher USB `0xC0` descrito en nuestros archivos corresponde solo a la aplicación Gotham build 169429, no a Bruce 337784. No asumir que el exploit llega a SDP igual desde todos los firmwares. Identificar cómo llegar a ROM SDP con un mecanismo oficial o conocido y seguro, sin usar comandos que modifiquen estado.
3. **Prueba temporal reproducible y sin escritura:** validar primero en un dispositivo de prueba autorizado, recuperable y no principal; obtener confirmación externa de ejecución en RAM, del retorno al firmware original tras reinicio, y de ausencia de escritura OTP/NOR.
4. **Examinar persistencia en unidad sacrificable:** revisar el procedimiento **con información de una fuente técnica primaria**, riesgos eléctricos/irreversibles de FIELD_RETURN, estado del sistema después de abrir y posibilidad de restaurar/arrancar firmware original. Sin evidencia y plan de recuperación: no usar en la unidad del usuario.
5. **Solo después:** portar los periféricos de hardware, USB y XUSB del proyecto al firmware realmente ejecutable; comprobar en Windows con trazas de enumeración y reconocer que una Xbox física plantea autenticación propia.

## Hechos que aún NO podemos afirmar

- Que `nxp-sdp-overrun` funcione en un Stadia cualquiera, que el código publicado se haya auditado o que sea seguro ejecutarlo.
- Que FIELD_RETURN se pueda activar sin daños ni perder la configuración original; que sea reversible o que el arranque original siga funcionando.
- Que las herramientas `fwlog-kit.zip` o el bootloader CDC sean un desbloqueo validado; que el firmware XInput propio se haya ejecutado en RT1061 físico.
- Que el supuesto exploit de **U-Boot SPL** afecte al bootloader de Stadia.
- Que la simulación de banco A/B de fases 101-102 represente la escritura real de OTP/HAB del Stadia.

**Decisión: P0 pasa de «imposible demostrar ruta» a «ruta publicada y testimonio de persistencia, pendiente de auditoría y réplica segura». Sin escritura real ni ejecución del exploit en este trabajo.**
