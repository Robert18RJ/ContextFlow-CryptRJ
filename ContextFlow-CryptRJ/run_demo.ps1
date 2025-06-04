# run_demo.ps1  –  Script todo-en-uno para PowerShell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[+] Checking venv" -ForegroundColor Cyan
if (-not (Test-Path ".venv")) {
    Write-Host "    -> Creating .venv ..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[+] Activating venv"
& .\.venv\Scripts\Activate.ps1

# Install Streamlit once
if (-not (pip show streamlit 2>$null)) {
    Write-Host "[+] Installing Streamlit ..." -ForegroundColor Yellow
    pip install --upgrade pip
    pip install streamlit
}

Write-Host "[+] Running app on http://localhost:8501" -ForegroundColor Green
streamlit run demo_streamlit.py
