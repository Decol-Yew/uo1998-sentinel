@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem Packet capture needs admin rights. If not elevated, relaunch via UAC.
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

".venv\Scripts\python.exe" sentinel.py
echo.
pause
