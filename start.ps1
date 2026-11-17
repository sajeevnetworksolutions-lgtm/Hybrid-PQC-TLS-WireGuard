# ==============================================================================
#   HYBRID POST-QUANTUM CRYPTOGRAPHY IN TLS 1.3 & WIREGUARD FRAMEWORK
#   M.Tech Cybersecurity Project 3 - Master Dissertation
#   PowerShell One-Click Startup Script
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  HYBRID POST-QUANTUM CRYPTOGRAPHY IN TLS 1.3 & WIREGUARD FRAMEWORK" -ForegroundColor White
Write-Host "  M.Tech Cybersecurity Project 3 - Master Dissertation" -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python Availability
Write-Host "[*] Checking Python availability..." -ForegroundColor Yellow
try {
    $pythonVer = & python --version 2>&1
    Write-Host "[+] Found $pythonVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python 3 was not found in your system PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/ and check 'Add to PATH'." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# 2. Create or Verify Virtual Environment
$venvPath = Join-Path $PSScriptRoot "venv"
$activateScript = Join-Path $venvPath "Scripts\Activate.ps1"

if (-not (Test-Path $activateScript)) {
    Write-Host "[*] Creating virtual environment in $venvPath ..." -ForegroundColor Yellow
    & python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create virtual environment!" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Existing virtual environment detected." -ForegroundColor Green
}

# 3. Activate Virtual Environment
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
try {
    & $activateScript
    Write-Host "[+] Virtual environment activated." -ForegroundColor Green
} catch {
    Write-Host "[WARNING] PowerShell script execution policy blocked Activate.ps1." -ForegroundColor Yellow
    Write-Host "Continuing with current Python interpreter..." -ForegroundColor Gray
}

# 4. Install / Verify Dependencies
Write-Host "[*] Installing / verifying dependencies from requirements.txt..." -ForegroundColor Yellow
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
& python -m pip install -r $reqFile --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] Quiet install had warnings. Retrying with verbose..." -ForegroundColor Yellow
    & python -m pip install -r $reqFile
}
Write-Host "[+] Dependencies verified." -ForegroundColor Green

# 5. Open Default Web Browser to Dashboard URL
Write-Host "[*] Opening browser to http://127.0.0.1:8000 ..." -ForegroundColor Cyan
Start-Process "http://127.0.0.1:8000"

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "  DASHBOARD READY AT: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  FastAPI Backend Running on Port 8000 (Press Ctrl+C to terminate)" -ForegroundColor White
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# 6. Start the FastAPI Uvicorn Server
& python -m uvicorn app:app --host 127.0.0.1 --port 8000
