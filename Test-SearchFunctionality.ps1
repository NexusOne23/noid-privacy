# =============================================================================
# TEST WINDOWS SEARCH FUNCTIONALITY
# =============================================================================
#
# PURPOSE: Check which search features work and which don't
#
# USAGE: .\Test-SearchFunctionality.ps1
#
# =============================================================================

Write-Host "`n============================================================================" -ForegroundColor Cyan
Write-Host "  WINDOWS SEARCH FUNCTIONALITY TEST" -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Cyan

Write-Host "`n=== ALLE SEARCH-RELATED REGISTRY KEYS ===" -ForegroundColor Yellow

$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

if (Test-Path $searchPath) {
    Write-Host "`n[HKLM Policies]" -ForegroundColor Cyan
    $policies = Get-ItemProperty -Path $searchPath
    
    # Show all properties except PS* properties
    $policies.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        $color = if ($_.Value -eq 0) { "Green" } elseif ($_.Value -eq 1) { "Red" } else { "Yellow" }
        Write-Host "  $($_.Name) = $($_.Value)" -ForegroundColor $color
    }
} else {
    Write-Host "[i] Kein HKLM Policy Path gefunden (alle Defaults)" -ForegroundColor Gray
}

Write-Host "`n[HKCU User Settings]" -ForegroundColor Cyan
$userSearchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
if (Test-Path $userSearchPath) {
    $userSettings = Get-ItemProperty -Path $userSearchPath -ErrorAction SilentlyContinue
    $userSettings.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | Select-Object -First 10 | ForEach-Object {
        $color = if ($_.Value -eq 0) { "Green" } elseif ($_.Value -eq 1) { "Red" } else { "Yellow" }
        Write-Host "  $($_.Name) = $($_.Value)" -ForegroundColor $color
    }
}

Write-Host "`n=== WINDOWS SEARCH SERVICE STATUS ===" -ForegroundColor Yellow
$searchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
if ($searchService) {
    Write-Host "  Status: $($searchService.Status)" -ForegroundColor $(if ($searchService.Status -eq 'Running') { "Green" } else { "Red" })
    Write-Host "  StartType: $($searchService.StartType)" -ForegroundColor White
} else {
    Write-Host "  [X] Windows Search Service nicht gefunden!" -ForegroundColor Red
}

Write-Host "`n=== INDEXING STATUS ===" -ForegroundColor Yellow
$indexPath = "HKLM:\SOFTWARE\Microsoft\Windows Search"
if (Test-Path $indexPath) {
    $setupCompleted = (Get-ItemProperty -Path $indexPath -Name "SetupCompletedSuccessfully" -ErrorAction SilentlyContinue).SetupCompletedSuccessfully
    if ($setupCompleted -eq 1) {
        Write-Host "  [OK] SetupCompletedSuccessfully = 1 (Indexing aktiv)" -ForegroundColor Green
    } else {
        Write-Host "  [X] SetupCompletedSuccessfully = $setupCompleted (Indexing NICHT aktiv!)" -ForegroundColor Red
    }
}

Write-Host "`n=== PROBLEMATISCHE KEYS (FALLS VORHANDEN) ===" -ForegroundColor Yellow
$problematicKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; BadValue = 1; Reason = "Blocks Settings/Control Panel search" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "PreventIndexingOutlook"; BadValue = 1; Reason = "Breaks Outlook search" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Search"; Name = "SetupCompletedSuccessfully"; BadValue = 0; Reason = "Disables indexing completely" }
)

$foundProblems = $false
foreach ($key in $problematicKeys) {
    if (Test-Path $key.Path) {
        $value = (Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue).($key.Name)
        if ($null -ne $value -and $value -eq $key.BadValue) {
            Write-Host "  [X] $($key.Name) = $value" -ForegroundColor Red
            Write-Host "      Reason: $($key.Reason)" -ForegroundColor Yellow
            Write-Host "      Fix: Remove-ItemProperty -Path '$($key.Path)' -Name '$($key.Name)'" -ForegroundColor Cyan
            $foundProblems = $true
        }
    }
}

if (-not $foundProblems) {
    Write-Host "  [OK] Keine problematischen Keys gefunden!" -ForegroundColor Green
}

Write-Host "`n=== EMPFOHLENE TESTS (MANUELL) ===" -ForegroundColor Yellow
Write-Host "  1. Windows-Taste druecken, tippe: 'Netzwerk'" -ForegroundColor White
Write-Host "     Erwartung: Netzwerkeinstellungen werden gefunden" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Windows-Taste druecken, tippe: 'Bluetooth'" -ForegroundColor White
Write-Host "     Erwartung: Bluetooth-Einstellungen werden gefunden" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Windows-Taste druecken, tippe: 'Systemsteuerung'" -ForegroundColor White
Write-Host "     Erwartung: Control Panel wird gefunden" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Windows-Taste druecken, tippe: 'Netzwerkadapter'" -ForegroundColor White
Write-Host "     Erwartung: Control Panel Network Adapters gefunden" -ForegroundColor Gray

Write-Host "`n============================================================================" -ForegroundColor Cyan
Write-Host "  BITTE TESTE DIE SUCHE UND BERICHTE ERGEBNISSE!" -ForegroundColor Yellow
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
