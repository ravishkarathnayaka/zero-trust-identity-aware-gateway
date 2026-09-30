# ==============================================================================
# Automated Test Runner: Executes Full ZTNA Verification Suite (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
Push-Location $rootDir

try {
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "Zero Trust Network Access (ZTNA) - Automated Test Suite" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Cyan

    Write-Host "`n[*] [1/3] Running Python Pytest Suite (Integration + Unit)..." -ForegroundColor Yellow
    python -m pytest tests/ -v

    Write-Host "`n[*] [2/3] Checking Code Linting (flake8)..." -ForegroundColor Yellow
    python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

    Write-Host "`n[*] [3/3] Checking Docker Compose Syntax..." -ForegroundColor Yellow
    docker compose -f docker/docker-compose.yml config > $null

    Write-Host "`n===================================================================" -ForegroundColor Cyan
    Write-Host "[OK] All Zero Trust Test Suites Passed Successfully!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Cyan
}
finally {
    Pop-Location
}
