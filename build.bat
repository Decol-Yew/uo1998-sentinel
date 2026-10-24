@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === UO1998Sentinel build [PyInstaller] ===
echo.

rem Use the venv created by setup.bat (scapy lives there). Sentinel does not use
rem anthropic/pydantic, so this build is small and has no heavy deps.
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run setup.bat first.
  pause
  exit /b 1
)

echo [1/2] Preparing PyInstaller...
".venv\Scripts\python.exe" -m pip install --upgrade pyinstaller
if errorlevel 1 ( echo [ERROR] Failed to install PyInstaller & pause & exit /b 1 )

echo [2/2] Building exe...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean ^
  --name UO1998Sentinel ^
  --onedir --windowed --uac-admin ^
  --icon app.ico ^
  --add-data "config.ini.example;." ^
  --add-data "app.ico;." ^
  --collect-all scapy ^
  sentinel.py
if errorlevel 1 ( echo [ERROR] Build failed & pause & exit /b 1 )

echo.
echo === Done: dist\UO1998Sentinel\UO1998Sentinel.exe ===
echo Put a config.ini (with your iface and self_names) next to the exe, or run it
echo in the same folder as the translator's config.ini.
echo NOTE: Npcap must be installed - https://npcap.com - WinPcap API-compatible Mode.
echo.
pause
