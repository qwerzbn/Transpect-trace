@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "PYTHONUTF8=1"
set "UV_PROJECT_ENVIRONMENT=%CD%\.venv"
rem A prepared environment can report or stop the guard without network access.
if not exist ".venv\Scripts\python.exe" goto prepare
if "%~1"=="" goto prepare
if /i "%~1"=="start" goto prepare
goto run

:prepare
where.exe uv.exe >nul 2>&1
if not errorlevel 1 goto sync
if exist ".venv\Scripts\python.exe" goto run
echo Install uv to prepare the project environment, then run guard-service.bat again. 1>&2
popd
exit /b 2

:sync
uv.exe sync --locked --inexact --extra native-build --quiet
if errorlevel 1 goto finish

:run
".venv\Scripts\python.exe" scripts\guard_hub.py %*

:finish
set "guard_status=%errorlevel%"
popd
exit /b %guard_status%
