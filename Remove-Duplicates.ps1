# Remove all 44 duplicates from RegistryChanges-Definition.ps1
# This script identifies and removes duplicate entries (same Path + Name)

$file = ".\Modules\RegistryChanges-Definition.ps1"
$content = Get-Content $file

Write-Host "Finding duplicates..." -ForegroundColor Yellow

# Track seen keys and lines to remove
$seen = @{}
$linesToRemove = @()
$i = 0

while ($i -lt $content.Count) {
    $line = $content[$i]
    
    # Start of entry
    if ($line -match '^\s*@\{') {
        $entryStart = $i
        $path = ""
        $name = ""
        $entryEnd = $i
        
        # Parse entry
        for ($j = $i; $j -lt [Math]::Min($i + 20, $content.Count); $j++) {
            if ($content[$j] -match "Path = '([^']+)'") {
                $path = $matches[1]
            }
            if ($content[$j] -match "Name = '([^']+)'") {
                $name = $matches[1]
            }
            if ($content[$j] -match '^\s*\},?\s*$') {
                $entryEnd = $j
                break
            }
        }
        
        if ($path -and $name) {
            $key = "$path|$name"
            
            if ($seen.ContainsKey($key)) {
                # This is a duplicate - mark for removal
                Write-Host "DUPLICATE at line $($entryStart + 1): $path\$name" -ForegroundColor Red
                $linesToRemove += @{
                    Start = $entryStart
                    End = $entryEnd
                    Key = $key
                }
            } else {
                $seen[$key] = $entryStart + 1
            }
        }
        
        $i = $entryEnd + 1
    } else {
        $i++
    }
}

Write-Host ""
Write-Host "Found $($linesToRemove.Count) duplicates" -ForegroundColor Yellow
Write-Host ""

# Remove duplicates (from end to start to preserve line numbers)
$newContent = $content
$removed = 0

foreach ($dup in ($linesToRemove | Sort-Object -Property Start -Descending)) {
    Write-Host "Removing lines $($dup.Start + 1)-$($dup.End + 1)" -ForegroundColor Cyan
    
    # Remove lines
    $before = $newContent[0..($dup.Start - 1)]
    $after = $newContent[($dup.End + 1)..($newContent.Count - 1)]
    $newContent = $before + $after
    $removed++
}

Write-Host ""
Write-Host "Removed $removed duplicates" -ForegroundColor Green
Write-Host "Original: $($content.Count) lines" -ForegroundColor White
Write-Host "New: $($newContent.Count) lines" -ForegroundColor White
Write-Host "Difference: $($content.Count - $newContent.Count) lines" -ForegroundColor Cyan

# Save
$newContent | Set-Content $file -Encoding UTF8
Write-Host ""
Write-Host "✅ Saved to $file" -ForegroundColor Green
