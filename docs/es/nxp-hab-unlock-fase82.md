# Fase 82 — Decodificación offline del comando HAB CSF UNLOCK

**27/10/2026.** Continuación de la [fase 81](nxp-rom-csf-fase81.md). El CSF de la imagen original del cargador RAM firmado contiene un comando `UNLOCK` que no aparece en la aplicación Bruce original. No se trata del comando USB del flashloader ni de «quitar la protección» de HAB CLOSED.

## Qué significa realmente UNLOCK

El [manual de NXP CST](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/202591/1/CST_UG.pdf) explica que `[Unlock]` especifica **funciones de motores periféricos que la ROM deja sin bloquear al salir**. Los motores posibles son **SRTC, CAAM, SNVS y OCOTP**. El argumento `Features` es una máscara de bits; algunas combinaciones con OCOTP requieren UID de 64 bits. **UNLOCK no sustituye la autenticación de firmas ni cambia el valor del fusible HAB CLOSED**.

El [código mantenido por NXP SPSDK](https://github.com/nxp-mcuxpresso/spsdk/blob/main/spsdk/image/hab/commands/cmd_unlock.py) fija el formato binario de HABv4: cabecera `0xB2`, longitud big-endian, identificador de motor en `header.param` (cuarto byte), máscara de funciones de 32 bits big-endian en los cuatro bytes siguientes. Si hay UID, son ocho bytes adicionales, que **este auditor jamás publica**. Los motores CAAM y OCOTP incluyen distintos nombres de flags; el resto se deja sin interpretar.

La documentación de NXP da ejemplos de `CAAM MID` para mantener accesibles registros de Job Ring/DECO, y de `OCOTP` para funciones específicas de fusibles. **La mera existencia de `UNLOCK` no permite deducir motor, flag o resultado físico**; por eso se extraen de la imagen exacta.

## Verificación reproducible

El nuevo [analizador SHA-pinned](../../tools/audit_hab_unlock_phase82.py) consume únicamente la imagen OEM original identificada por hash mediante la [fase 81](../../tools/audit_nxp_rom_advisories_phase81.py), localiza el comando `0xB2` en el CSF y expone únicamente posición relativa, código de motor, máscara y nombres de flags documentados. Puede leer cargador RAM, Bruce y el bootloader A privado si el propietario conserva el original.

Las [pruebas sintéticas](../../tests/test_hab_unlock_phase82.py) comprueban correspondencia de máscaras, flags desconocidos, ausencia de UID en informes, longitudes malformadas y rechazo de imágenes con SHA incorrecto. [CI de muestras OEM públicas](../../.github/workflows/nxp-rom-advisories-phase81.yml) descarga archivos temporalmente y los elimina. No se incluyen bytes de UID, seriales ni firmware propietario en el repositorio.

```sh
python -m unittest tests/test_hab_unlock_phase82.py -v
python -m tools.audit_hab_unlock_phase82 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader --out local/unlock.json
python -m tools.audit_hab_unlock_phase82 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod --out local/bruce-unlock.json
```

## Hallazgo confirmado en la imagen OEM original

**[Evidencia JSON fijada](../../evidence/nxp-hab-unlock-phase82.json)** · [GitHub Actions con muestra SHA-pinned](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40556380124)

| Campo | Cargador RAM firmado | Bruce firmado |
|---|---|---|
| Número de comandos UNLOCK | **1** | **0** |
| Offset dentro del CSF | **0x48** | — |
| Selector de motor | **0x21: OCOTP** | — |
| Máscara de funciones | **0x00000002** | — |
| Nombre según NXP | **SRK_REVOKE** | — |
| UID en el comando | **No** | — |

**Interpretación precisa:** el CSF original de Google pide a HAB que **no bloquee la función de revocación SRK de OCOTP** al salir de ROM. No ejecuta una revocación; no prueba que un tercero pueda modificar los fusibles, y no cambia la necesidad de firma válida para arrancar la aplicación. La revocación SRK sería una modificación irreversible del estado de confianza y no debe ensayarse en el mando único.

La CI ahora comprueba explícitamente estos seis campos sobre el archivo OEM de SHA-256 fijo; las 16 pruebas sintéticas de las fases 81/82 también han pasado. El estado real de OCOTP después del arranque sigue sin medirse.

## Interpretación

La comprobación confirma únicamente lo que **solicita el CSF original autenticado**; no demuestra el comportamiento interno de BootROM ni el estado posterior de los registros de seguridad. El equipo físico analizado sigue en HAB CLOSED y no se conoce su versión de HAB. La cuestión de CVE-2022-45163 (potencial divulgación de memoria por SDP) es independiente; nada aquí demuestra firmware propio ni bypass de autenticación.

**Sin mando conectado, sin comandos USB, sin programación de memoria persistente y sin eFuses.**
