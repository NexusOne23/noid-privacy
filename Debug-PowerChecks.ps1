# DEBUG SCRIPT - Test Power Checks
Write-Host "=== HIBERNATE CHECK ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "[TEST 1] Raw powercfg output:" -ForegroundColor Yellow
powercfg /availablesleepstates

Write-Host ""
Write-Host "[TEST 2] Hibernate lines only:" -ForegroundColor Yellow
$sleepStates = powercfg /availablesleepstates 2>&1
$hibernateLines = $sleepStates | Where-Object { $_ -match '(Hibernate|Ruhezustand)' }
$hibernateLines | ForEach-Object { Write-Host "  > $_" -ForegroundColor Gray }

Write-Host ""
Write-Host "[TEST 3] Check for 'not/nicht':" -ForegroundColor Yellow
$unsupported = $hibernateLines | Where-Object { $_ -match '(not|nicht)' }
Write-Host "  Unsupported count: $($unsupported.Count)" -ForegroundColor $(if ($unsupported.Count -eq 0) { 'Green' } else { 'Red' })
if ($unsupported.Count -gt 0) {
    $unsupported | ForEach-Object { Write-Host "  [X] $_" -ForegroundColor Red }
}

Write-Host ""
Write-Host "[TEST 4] Final result:" -ForegroundColor Yellow
$result = ($unsupported.Count -eq 0)
Write-Host "  Hibernate Available: $result" -ForegroundColor $(if ($result) { 'Green' } else { 'Red' })

Write-Host ""
Write-Host "=== DISPLAY TIMEOUT ===" -ForegroundColor Cyan
Write-Host ""

$SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"
$VIDEOIDLE = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"

Write-Host "[TEST 5] Active Power Scheme:" -ForegroundColor Yellow
$activeScheme = (powercfg /getactivescheme 2>&1 | Out-String) -replace '.*GUID[:\s]+([a-f0-9\-]+).*', '$1'
Write-Host "  GUID: $activeScheme" -ForegroundColor Gray

Write-Host ""
Write-Host "[TEST 6] Display Timeout Value:" -ForegroundColor Yellow
$output = powercfg /GETACVALUEINDEX $activeScheme $SUB_VIDEO $VIDEOIDLE 2>&1 | Out-String
Write-Host "  Raw output: $output" -ForegroundColor Gray

if ($output -match '0x([0-9a-f]+)') {
    $seconds = [Convert]::ToInt32($matches[1], 16)
    $minutes = $seconds / 60
    Write-Host "  Hex: 0x$($matches[1])" -ForegroundColor Gray
    Write-Host "  Seconds: $seconds" -ForegroundColor Gray
    Write-Host "  Minutes: $minutes" -ForegroundColor $(if ($minutes -eq 10) { 'Green' } else { 'Red' })
}
else {
    Write-Host "  [X] Could not parse output!" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== HIBERNATE TIMEOUT ===" -ForegroundColor Cyan
Write-Host ""

$SUB_SLEEP = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
$HIBERNATEIDLE = "9d7815a6-7ee4-497e-8888-515a05f02364"

Write-Host "[TEST 7] Hibernate Timeout Value:" -ForegroundColor Yellow
$output = powercfg /GETACVALUEINDEX $activeScheme $SUB_SLEEP $HIBERNATEIDLE 2>&1 | Out-String
Write-Host "  Raw output: $output" -ForegroundColor Gray

if ($output -match '0x([0-9a-f]+)') {
    $seconds = [Convert]::ToInt32($matches[1], 16)
    $minutes = $seconds / 60
    Write-Host "  Hex: 0x$($matches[1])" -ForegroundColor Gray
    Write-Host "  Seconds: $seconds" -ForegroundColor Gray
    Write-Host "  Minutes: $minutes" -ForegroundColor $(if ($minutes -eq 30) { 'Green' } else { 'Red' })
}
else {
    Write-Host "  [X] Could not parse output!" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Run this script on your VM and send me the output!" -ForegroundColor Yellow
