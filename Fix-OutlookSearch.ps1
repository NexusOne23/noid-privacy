#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Fixes Outlook Search by restoring Windows Search functionality
    
.DESCRIPTION
    This script fixes the Outlook email search issue caused by SetupCompletedSuccessfully = 0.
    
    PROBLEM:
    - Windows Search Indexer was disabled (SetupCompletedSuccessfully = 0)
    - Outlook relies on Windows Search for email indexing
    - Result: Outlook search doesn't work
    
    SOLUTION:
    - Set SetupCompletedSuccessfully = 1 (normal value)
    - Restart Windows Search service
    - Rebuild Outlook search index (optional, automatic instructions)
    
.EXAMPLE
    .\Fix-OutlookSearch.ps1
    
.NOTES
    Version: 1.0
    Created: 2025-11-04
    Reason: SetupCompletedSuccessfully = 0 breaks Windows Search and Outlook
#>

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " FIX: Outlook Search (Windows Search)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check current value
$searchPath = "HKLM:\SOFTWARE\Microsoft\Windows Search"
$currentValue = (Get-ItemProperty -Path $searchPath -Name "SetupCompletedSuccessfully" -ErrorAction SilentlyContinue).SetupCompletedSuccessfully

Write-Host "[INFO] Current value: SetupCompletedSuccessfully = $currentValue" -ForegroundColor Yellow

if ($currentValue -eq 1) {
    Write-Host "[OK] Windows Search is already configured correctly!" -ForegroundColor Green
    Write-Host ""
    Write-Host "If Outlook search still doesn't work:" -ForegroundColor Yellow
    Write-Host "  1. Open Outlook" -ForegroundColor Gray
    Write-Host "  2. File > Options > Search > Indexing Options" -ForegroundColor Gray
    Write-Host "  3. Click 'Rebuild' to recreate the search index" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Host "[FIX] Setting SetupCompletedSuccessfully = 1..." -ForegroundColor Cyan

try {
    Set-ItemProperty -Path $searchPath -Name "SetupCompletedSuccessfully" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "[OK] Registry key fixed!" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to fix registry key: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[FIX] Restarting Windows Search service..." -ForegroundColor Cyan

try {
    Restart-Service -Name "WSearch" -Force -ErrorAction Stop
    Write-Host "[OK] Windows Search service restarted!" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Failed to restart service: $_" -ForegroundColor Yellow
    Write-Host "[INFO] Please restart manually or reboot Windows" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " FIX COMPLETED!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS FOR OUTLOOK:" -ForegroundColor Cyan
Write-Host "  1. Wait 2-5 minutes for Windows Search to re-initialize" -ForegroundColor Gray
Write-Host "  2. Open Outlook" -ForegroundColor Gray
Write-Host "  3. If search still doesn't work: File > Options > Search > Indexing Options > Rebuild" -ForegroundColor Gray
Write-Host "  4. Index rebuild takes 5-30 minutes (depends on mailbox size)" -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: Search will work again automatically after index rebuild!" -ForegroundColor Green
Write-Host ""
