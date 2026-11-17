@echo off
setlocal enabledelayedexpansion

title Hybrid Post-Quantum Cryptography Framework (M.Tech Project 3)
echo ==============================================================================
echo   HYBRID POST-QUANTUM CRYPTOGRAPHY IN TLS 1.3 ^& WIREGUARD FRAMEWORK
echo   M.Tech Cybersecurity Project 3 - Master Dissertation
echo ==============================================================================
echo.

:: 1. Check Python availability
echo [*] Checking Python availability...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python 3 is not found in your system PATH!
    echo Please install Python 3.10+ from https://www.python.org/ and ensure
    echo "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PY_VER=%%i
echo [+] Found %PY_VER%

:: 2. Create or verify Virtual Environment
if not exist "venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment in .\venv ...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo [+] Virtual environment created successfully.
) else (
    echo [+] Virtual environment detected in .\venv.
)

:: 3. Activate Virtual Environment
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to activate virtual environment!
    pause
    exit /b 1
)

:: 4. Install / Verify Dependencies
echo [*] Checking dependencies in requirements.txt...
python -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Some dependencies had warnings during install. Retrying with verbose...
    python -m pip install -r requirements.txt
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to install required packages!
        pause
        exit /b 1
    )
)
echo [+] Dependencies verified.

:: 5. Launch Browser after 2 seconds in background
echo [*] Launching local web dashboard...
start "" http://127.0.0.1:8000

echo.
echo ==============================================================================
echo   DASHBOARD READY AT: http://127.0.0.1:8000
echo   FastAPI Backend Starting on Port 8000 (Press Ctrl+C to terminate)
echo ==============================================================================
echo.

:: 6. Start the FastAPI Uvicorn Server
python -m uvicorn app:app --host 127.0.0.1 --port 8000

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Server terminated with an error!
    pause
)
