@echo off
setlocal
if not defined NO_COLOR if not defined ATLAS_COLOR set "ATLAS_COLOR=always"
if exist "%~dp0.venv-windows\Scripts\python.exe" goto windowsvenv
if exist "%~dp0.venv\Scripts\python.exe" goto venv
where py.exe >nul 2>&1
if not errorlevel 1 goto pylauncher
where python.exe >nul 2>&1
if not errorlevel 1 goto python
echo Python is required. Install Python 3.10 or newer, then try again.
exit /b 2
:windowsvenv
"%~dp0.venv-windows\Scripts\python.exe" "%~dp0atlas.py" %*
exit /b %errorlevel%
:venv
"%~dp0.venv\Scripts\python.exe" "%~dp0atlas.py" %*
exit /b %errorlevel%
:pylauncher
py -3 "%~dp0atlas.py" %*
exit /b %errorlevel%
:python
python "%~dp0atlas.py" %*
exit /b %errorlevel%
