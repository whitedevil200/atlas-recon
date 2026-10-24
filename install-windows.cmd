@echo off
setlocal
where py.exe >nul 2>&1
if not errorlevel 1 goto pylauncher
where python.exe >nul 2>&1
if not errorlevel 1 goto python
echo Python is required. Install Python 3.10 or newer, then try again.
exit /b 2
:pylauncher
py -3 -m venv "%~dp0.venv-windows"
if errorlevel 1 exit /b 2
goto packages
:python
python -m venv "%~dp0.venv-windows"
if errorlevel 1 exit /b 2
:packages
"%~dp0.venv-windows\Scripts\python.exe" -m pip install --require-hashes -r "%~dp0requirements-runtime.lock"
if errorlevel 1 exit /b 2
"%~dp0.venv-windows\Scripts\python.exe" -m pip install --no-deps "%~dp0."
if errorlevel 1 exit /b 2
if "%ATLAS_SKIP_ENGINES%"=="1" goto complete
"%~dp0.venv-windows\Scripts\python.exe" "%~dp0atlas.py" setup-engines
if errorlevel 1 exit /b 2
:complete
echo Installed. In PowerShell, run .\atlas.cmd to open the colorful menu.
echo Run .\atlas.cmd doctor to check dependencies.
exit /b 0
