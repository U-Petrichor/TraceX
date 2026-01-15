@echo off
echo [INFO] Starting TraceX Web Dashboard...
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Install dependencies (Optional, can be commented out if already installed)
echo [INFO] Checking dependencies...
pip install -r backend\requirements.txt

REM Start the server
echo [INFO] Server running at http://localhost:8000
set PYTHONPATH=..;%PYTHONPATH%
python backend\main.py
pause