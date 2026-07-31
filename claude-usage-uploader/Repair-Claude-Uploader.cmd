@echo off
setlocal
title Claude Usage Uploader Repair
rem Prefer the newest repair script present, so one .cmd serves whichever
rem version's kit it was shipped alongside.
set "REPAIR_PS1=%~dp0repair-v2.0.8.ps1"
if not exist "%REPAIR_PS1%" set "REPAIR_PS1=%~dp0repair-v2.0.7.ps1"
if not exist "%REPAIR_PS1%" set "REPAIR_PS1=%~dp0repair-v2.0.6.ps1"
if not exist "%REPAIR_PS1%" set "REPAIR_PS1=%~dp0repair-v2.0.5.ps1"
if not exist "%REPAIR_PS1%" (
  echo ERROR: no repair-v2.0.x.ps1 found next to this file.
  echo Copy the WHOLE RepairKit folder, not just this shortcut.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%REPAIR_PS1%"
if errorlevel 1 (
  echo.
  echo Repair did not finish. Copy the error above and send it to IT.
) else (
  echo.
  echo Claude Usage Uploader repair completed successfully.
)
echo.
pause
endlocal
