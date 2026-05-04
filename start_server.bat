@echo off
REM ============================================================
REM  start_server.bat - PowerShell shim
REM  ASCII only - encoding-safe on any Windows codepage.
REM  Real logic is in start_server.ps1 (UTF-8 safe).
REM ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_server.ps1" %*
if errorlevel 1 pause
