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
"%~dp0.venv-windows\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 exit /b 2
echo Installed. In PowerShell, run .\atlas.cmd to open the colorful menu.
echo Run .\atlas.cmd doctor to check dependencies.
exit /b 0
