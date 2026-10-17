@echo off
setlocal

set "PROJECT_DIR=%~dp0"
set "PROJECT_PYTHON=%PROJECT_DIR%.venv\Scripts\python.exe"

if not exist "%PROJECT_PYTHON%" (
    echo Project virtual environment was not found:
    echo   %PROJECT_PYTHON%
    echo Create it once with: py -3.13 -m venv .venv
    echo Then install dependencies with: .\run.bat -m pip install -r requirements-dev.txt
    exit /b 1
)

pushd "%PROJECT_DIR%" >nul
"%PROJECT_PYTHON%" %*
set "PROJECT_EXIT_CODE=%ERRORLEVEL%"
popd >nul
exit /b %PROJECT_EXIT_CODE%
