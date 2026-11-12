@echo off
setlocal
cd /d "%~dp0"
set "NORMA_DIR=%~dp0"
set "NORMA_SELF=%~f0"
set "NORMA_MODE="
title NORMA

rem Administrator rights are needed (WinDivert driver).
fltmc >nul 2>&1
if errorlevel 1 (
  if /i "%~1"=="elevated" (
    echo Administrator rights were not granted. Please run NORMA.bat again and accept the UAC prompt.
    pause
    exit /b 1
  )
  powershell -NoProfile -Command "Start-Process -FilePath $env:NORMA_SELF -ArgumentList 'elevated' -Verb RunAs"
  exit /b
)

if not exist "%~dp0data\logs" mkdir "%~dp0data\logs" >nul 2>&1

rem The main script is read explicitly as UTF-8, so Russian text survives even if the BOM was lost.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Join-Path $env:NORMA_DIR 'app\norma.ps1'; $t = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8); & ([ScriptBlock]::Create($t))"
echo.
pause
