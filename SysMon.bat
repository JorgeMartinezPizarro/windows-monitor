@echo off
setlocal
cd /d "%~dp0"

rem ===== Configuracion =====
rem Puerto local del monitor
set "PORT=8787"
rem Como abrirlo: app = ventana de Edge sin barras ^| browser = navegador por defecto ^| none = no abrir
set "MODE=app"
rem Tambien se puede pasar como argumento:  SysMon.bat browser
if not "%~1"=="" set "MODE=%~1"
rem Puerto del "Remote Web Server" de LibreHardwareMonitor (temperatura de CPU y discos). 0 = desactivado
set "LHM_PORT=8085"

rem ===== Compila sysmon.exe si no existe o si sysmon.cs es mas nuevo =====
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

set "BUILD=1"
if exist "sysmon.exe" (
  set "BUILD=0"
  for /f "delims=" %%F in ('dir /b /o:d "sysmon.*" ^| findstr /i /x "sysmon.cs sysmon.exe"') do set "NEWEST=%%F"
)
if /i "%NEWEST%"=="sysmon.cs" set "BUILD=1"

if "%BUILD%"=="1" (
  echo Compilando sysmon.exe...
  "%CSC%" /nologo /optimize+ /out:sysmon.exe /r:System.Management.dll /r:System.Web.Extensions.dll sysmon.cs
  if errorlevel 1 (
    echo.
    echo No se pudo compilar sysmon.cs. Si SysMon ya esta abierto, cierralo y vuelve a intentarlo.
    pause
    exit /b 1
  )
)

rem ===== Arranca el servidor minimizado; el propio servidor abre la ventana =====
start "SysMon" /min "%~dp0sysmon.exe" %PORT% %MODE% --lhm=%LHM_PORT%
