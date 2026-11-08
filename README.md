# Sistema

Monitor de sistema minimalista para Windows. Muestra en una web local, actualizada cada segundo:

- **CPU**: uso total, frecuencia real, uso por hilo, procesos y temperatura (con LibreHardwareMonitor).
- **Memoria RAM**: en uso, disponible y memoria confirmada.
- **GPU** y **VRAM**: uso, memoria, reloj, consumo, ventilador y temperatura.
- **Disco**: actividad, lectura y escritura por disco, y espacio libre por unidad. Avisa si un disco deja de responder.
- **Red**: descarga y subida, total y por adaptador.
- **Temperatura**: CPU, GPU, SSD y zonas ACPI.

Cada tarjeta incluye una gráfica de los últimos 60 segundos. Si pasas el ratón por encima, ves el valor de cada segundo.

## Requisitos

- Windows 10 u 11.
- No hay que instalar nada: el compilador de C# y .NET Framework 4 ya vienen con Windows.
- Opcional: [LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases) para la temperatura de la CPU y de los discos.

## Uso

Haz doble clic en **`SysMon.bat`**.

- La primera vez compila `sysmon.exe` a partir de `sysmon.cs`, en unos segundos. Solo vuelve a compilar si cambias `sysmon.cs`.
- Arranca el servidor en una ventana de consola minimizada llamada *SysMon* y abre la web en una ventana de Edge sin barras.
- **Para cerrarlo**, cierra la ventana de consola *SysMon*. Cerrar la web no detiene el servidor.
- Si ya está en marcha, volver a ejecutar el `.bat` solo abre la ventana.

También puedes abrirla en cualquier navegador: <http://localhost:8787>

## Configuración

Las opciones están al principio de `SysMon.bat`:

| Variable   | Por defecto | Qué hace |
|------------|-------------|----------|
| `PORT`     | `8787`      | Puerto local de la web. |
| `MODE`     | `app`       | `app`: ventana de Edge sin barras · `browser`: navegador por defecto · `none`: no abre nada. |
| `LHM_PORT` | `8085`      | Puerto del servidor web de LibreHardwareMonitor. `0` lo desactiva. |

El modo también se puede pasar como argumento, por ejemplo `SysMon.bat browser`.

## Temperatura de la CPU

Windows no da la temperatura de la CPU sin un driver especial. Para tenerla, *Sistema* lee los datos de LibreHardwareMonitor:

1. Descarga LibreHardwareMonitor y ábrelo **como administrador**.
2. Activa *Options → Remote Web Server* (puerto 8085).
3. Recomendado: activa también *Options → Run On Windows Startup* y *Start Minimized*.

*Sistema* lo detecta en unos segundos, sin reiniciar. Si Windows muestra un aviso del firewall, puedes cancelarlo: la conexión es dentro de tu propio equipo.

Sin LibreHardwareMonitor se siguen mostrando la temperatura de la GPU (NVIDIA) y las zonas ACPI. Las zonas ACPI son sensores de la placa base, no del procesador.

## Archivos

| Archivo       | Qué es |
|---------------|--------|
| `SysMon.bat`  | Lanzador: compila si hace falta y arranca el servidor. |
| `sysmon.cs`   | Servidor y recolector de métricas (C#). |
| `index.html`  | La web (HTML, CSS y JavaScript en un solo archivo). Los cambios se ven al recargar con F5, sin recompilar. |
| `sysmon.exe`  | Se genera al compilar. Si lo borras, se vuelve a crear. |

## Cómo funciona

Un único proceso (`sysmon.exe`) toma una muestra por segundo y la sirve en `http://localhost:8787/api/stats` como JSON:

- **CPU, disco y procesos**: contadores de rendimiento de Windows (PDH). Funcionan con Windows en cualquier idioma.
- **RAM**: API de Windows (`GlobalMemoryStatusEx`).
- **GPU y VRAM**: NVML, la biblioteca del driver de NVIDIA. Con otras tarjetas usa los mismos contadores que el Administrador de tareas.
- **Red**: estadísticas de los adaptadores de .NET. Los adaptadores virtuales (Hyper-V, VirtualBox, VPN) se muestran, pero no suman al total.
- **Temperaturas**: LibreHardwareMonitor (CPU y discos), NVML (GPU) y zonas térmicas ACPI.

El servidor solo escucha en `localhost`, así que no es accesible desde otros equipos. Consume menos del 1 % de un núcleo y unos 65 MB de RAM. La web deja de pedir datos mientras la pestaña está oculta.

## Problemas frecuentes

- **"No se pudo compilar sysmon.cs"**: lo más habitual es que *Sistema* siga abierto y el `.exe` esté en uso. Cierra la ventana *SysMon* y vuelve a ejecutar el `.bat`.
- **"El puerto 8787 ya está en uso"**: otra aplicación usa ese puerto. Cambia `PORT` en `SysMon.bat`.
- **No aparece la temperatura de la CPU**: comprueba que LibreHardwareMonitor está abierto como administrador y que <http://localhost:8085/data.json> responde en el navegador.
- **Un disco pone "Sin respuesta"** (o 100 % activo con 0 B/s): el disco tiene peticiones pendientes y no termina ninguna. No es un error de medida, porque Windows cuenta los bytes cuando cada petición termina. Si pasa a menudo con un disco USB, mira en el Visor de eventos (*Registros de Windows → Sistema*) si hay avisos 129 (reinicio del dispositivo) o 153 (operación repetida). Suelen deberse al cable, al puerto, a la alimentación, a la caja USB o al propio disco.
