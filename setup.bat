@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === uo1998-sentinel setup ===
echo [Npcap] Packet capture needs Npcap. If missing, install from https://npcap.com
echo         and check "WinPcap API-compatible Mode".
echo.
where py >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found. Install Python 3.13 from https://www.python.org
  pause
  exit /b 1
)
echo [1/3] Creating virtual environment...
rem Sentinel only needs scapy, so any recent Python works. Prefer a stable one.
set "PYLAUNCH="
for %%V in (3.13 3.12 3.11 3.14) do if not defined PYLAUNCH ( py -%%V -c "import sys" >nul 2>&1 && set "PYLAUNCH=py -%%V" )
if not defined PYLAUNCH set "PYLAUNCH=py"
echo Using Python: %PYLAUNCH%
%PYLAUNCH% -m venv .venv
echo [2/3] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
echo [3/3] Preparing config...
if not exist config.ini copy config.ini.example config.ini >nul
echo.
echo Setup complete.
echo Next: open config.ini, set iface and your character names (self_names),
echo then run run.bat to start Sentinel.
echo (Or just run it in the same folder as the translator's config.ini.)
pause
