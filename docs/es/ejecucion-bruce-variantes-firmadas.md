# Bruce y actualizador firmado: puertas de ejecución alternativas (investigación offline)

**25/10/2026 · PR #31.** Esta revisión sustituye la búsqueda de otras escrituras
masivas de `FillMemory` por un contraste independiente de la **aplicación
original**, la ruta de actualización archivada y tres variantes OEM firmadas
`prod/stage/dev`. No se enviaron comandos al mando, ni se programó flash.

## 1. Identidad de las muestras

El archivo público
[StadiaMemories/firmware/bruce_pvt_a_prod_signed.bin](https://github.com/StadiaMemories/firmware/blob/main/bruce_pvt_a_prod_signed.bin)
tiene el mismo tamaño (1.050.984 bytes) y **el mismo SHA-256 exacto**
`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`
que la muestra Bruce facilitada anteriormente. Eso permite reproducir su
análisis en GitHub Actions sin publicar una nueva extracción.

**El archivo firmado no es una lectura íntegra de la aplicación instalada
en el mando concreto.** La igualdad entre dos archivos de actualización no
demuestra igualdad con la flash física.

## 2. Límite HAB/CMS y supuesto «espacio no firmado»

Las firmas RSA/CMS de la imagen original se verificaron matemáticamente
con los certificados incluidos en su CSF. El bloque de contenido de
aplicación autentificado cubre **`[0x000000,0xFF030)`**
(1.044.528 bytes). El resto **no es automáticamente ejecutable**:

| Intervalo del archivo | Bytes | Interpretación |
|---|---:|---|
| `0x000000..0xFEFFF` | 1.044.480 | Contenido de la aplicación autenticado |
| `0xFF000..0xFF02F` | 48 | IVT incluido en el bloque autenticado |
| `0xFF030..0xFF077` | 72 | Comandos CSF de autenticación |
| `0xFF078..final` | 6.384 | Certificados, firmas u otro material final |

Una búsqueda de **palabras de 32 bits alineadas** en el bloque
autenticado cuyo valor apunta a direcciones XIP del tramo a partir
de `0xFF030` encontró **una única referencia**: `0xFF018`
contiene `0x6013F030`, precisamente el puntero **IVT → CSF**.
No es una función ni un salto Thumb. No se detectó una referencia
**alineada y directa** a ese tramo con apariencia de entrada de código.

**Límite:** ese barrido no cubre direcciones calculadas, referencias
sin alinear, memoria runtime, saltos indirectos ni todo el control
de flujo. Que existan bytes fuera del bloque de aplicación autenticado
no demuestra una extensión de código ejecutable o bypass HAB.

## 3. Diferencias reales entre prod, stage y dev

Se verificaron los **tres archivos OEM archivados**, cada uno con dos
firmas CMS/RSA válidas usando los certificados incluidos. Para proteger
su procedencia, el auditor exige el Git blob SHA-1 exacto de cada versión
antes de comparar.

| Comparación con prod | Stage | Dev |
|---|---:|---:|
| Diferencias en el código `[0,0xFF000)` | **0 bytes** | **0 bytes** |
| Diferencias en todo el bloque autenticado `[0,0xFF030)` | **0 bytes** | **0 bytes** |
| Diferencias después de `0xFF030` | 3.182 bytes | 3.192 bytes |
| Primera diferencia del archivo | `0xFF03A` | `0xFF03A` |
| ¿Comparten alguna clave pública de certificado incluido con prod? | **No** | **No** |
| ¿Probado que arranquen en el mando de producción HAB CLOSED? | No | No |

**Hallazgo:** `dev` y `stage` no contienen un programa Bruce
alternativo diferente de `prod` en esta generación archivada.
Las diferencias se concentran en el material posterior al bloque
autenticado, incluyendo material de firma. Por tanto, **cambiar entre
estos tres ficheros no permitiría instalar lógica propia ni obtener
un firmware de desarrollo con nuevas funciones de ejecución**.

Una firma criptográficamente válida con certificados incluidos **no
demuestra confianza por parte de los fusibles SRK del mando**.
No se ha ensayado flashear otras variantes sobre una unidad prod.

## 4. ¿Proporciona el actualizador oficial otra entrada de ejecución?

Se contrastó por hash y por código el
[JavaScript original archivado](protocolo-actualizador-webhid.md):

- En USB normal `18D1:9400`, la ruta identificada consulta versión/batería.
- El flujo de actualización usa **ROM SDP `1FC9:0135`** para transferir
  un **cargador RAM firmado** y saltar a él, y después usa el
  **flashloader firmado `15A2:0073`** para borrar/escribir la imagen.
- La aplicación Bruce expone un callback estático de **HID tag 5**
  asociado a controles de dos canales (probablemente vibración);
  **no se ha trazado hasta un comando de firmware**.
- Las comprobaciones de cabecera y partición en el JS no
  equivalen a autorización criptográfica; ésta depende del
  arranque, las firmas y la confianza efectiva del hardware.

No hay evidencia de que esa ruta **acepte una aplicación alterada con
código propio**, ni de una recuperación fiable en caso de escritura
interrumpida. El bootloader A/B no ofrece una restauración ya
demostrada para una imagen propia.

## 5. Decisión de esta etapa

**Sin ejecución propia demostrada.** La comparación independiente
**descarta la hipótesis concreta de «dev/stage trae código alternativo»**
y el único puntero alineado al CSF tiene función criptográfica
estructural, no de ejecución. Esta investigación **no prueba**
imposibilidad matemática de otros fallos, pero seguir ampliando
búsquedas estáticas sin entrada host alcanzable y recuperable no
justifica experimentar en el mando único.

Para reabrir la vía de firmware nativo debería aparecer **evidencia
independiente de ejecución controlable y método de recuperación
verificado**, no únicamente un binario OEM válido, un buffer HID o
un trailer no autenticado. Se mantienen cerradas todas las operaciones
de escritura física o fusión de eFuses.

### Reproducción

```sh
python -m unittest tests.test_signed_app_host_boundary tests.test_signed_bruce_variants -v
python -m tools.audit_signed_app_host_boundary local/bruce_pvt_a_prod_signed.bin local/app_combined.js
python -m tools.audit_signed_bruce_variants local/bruce_pvt_a_prod_signed.bin local/bruce_dvt_a_stage_signed.bin local/bruce_dvt_a_dev_signed.bin
```

El workflow hace descargas temporales de los archivos públicos, verifica
identidad/hash, extrae solo JSON saneado y elimina los archivos.
[Verificación real sobre las tres variantes y el JS archivado](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40239207683).
