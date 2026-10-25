# Diagnóstico de entrada en Windows — fase 32

El mando conectado sigue en USB normal `18D1:9400`, con Bruce **337784**.
La consulta de estado reproduce los ocho bytes registrados anteriormente:
`78 27 05 00 D5 95 02 00`. Windows enumera WinUSB en la interfaz 00 y HID
en la 01. La [evidencia](../../evidence/phase32-device-status.json) separa
estas observaciones de las funciones todavía no probadas.

En la ejecución real del 25 de octubre de 2026, WinMM anunció 16 posiciones
compatibles pero ninguna coincidencia automática. La consulta explícita del
índice 0 devolvió error 165 (`JOYERR_UNPLUGGED`). No se obtuvieron muestras
de entrada: la presencia HID no se presenta como prueba de botones o sticks.

`tools/Test-StadiaInput.ps1` consulta únicamente WinMM; no cambia controladores,
emparejamientos ni firmware y no envía comandos de salida al mando:

```powershell
./tools/Test-StadiaInput.ps1
./tools/Test-StadiaInput.ps1 -Seconds 20 > input-local.json
```

La selección automática exige los identificadores de fabricante/producto
`18D1:9400` comunicados por WinMM. Si el controlador utiliza otros identificadores,
se puede indicar un índice conocido con `-JoystickIndex 0`; en ese caso la
identidad queda explícitamente sin verificar. El índice es base cero. La duración
admitida es 1–60 segundos y el intervalo, 10–1000 ms.

El JSON incluye muestras correctas/fallidas, mínimos y máximos observados por eje,
máscara de botones vistos y valores POV (centésimas de grado; 65535 indica reposo).
Solo se incluyen los ejes opcionales y POV anunciados por las capacidades WinMM.
Para comprobar recorrido, mover los sticks y gatillos y pulsar botones durante
el intervalo; las muestras en reposo solo comprueban lectura, no funcionamiento
completo. La máscara usa el bit cero para el botón 1.

WinMM es una vista antigua de entrada: no detectar el mando aquí no demuestra
ausencia de HID o Bluetooth. No prueba XInput, vibración, compatibilidad Xbox
ni el puente ESP32. No se incluyen números de serie, rutas de instancia ni nombres
personalizados del dispositivo en la salida.

Referencias de API: [JOYCAPSW](https://learn.microsoft.com/en-us/windows/win32/api/joystickapi/ns-joystickapi-joycapsw)
y [funciones joystick](https://learn.microsoft.com/en-us/windows/win32/api/joystickapi/).
