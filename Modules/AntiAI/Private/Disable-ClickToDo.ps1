#Requires -Version 5.1

<#
.SYNOPSIS
    Disables Click to Do (screenshot AI analysis).

.DESCRIPTION
    Applies DisableClickToDo = 1 policy (Device and User scope).
    
    Click to Do takes on-demand screenshots and analyzes them with AI to suggest actions:
    - Extract and copy text
    - Search for selected content
    - Call detected phone numbers
    - Email detected addresses
    
    Disabling prevents all screenshot AI analysis and action suggestions.

.EXAMPLE
    Disable-ClickToDo
#>
function Disable-ClickToDo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Click to Do (screenshot AI analysis)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Click to Do (DisableClickToDo=1)" -Module "AntiAI"
            $result.Applied++
            $result.Success = $true
            return $result
        }
        
        # Device-scope (HKLM)
        $devicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $devicePath)) {
            New-Item -Path $devicePath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $devicePath" -Module "AntiAI"
        }
        
        $existing = Get-ItemProperty -Path $devicePath -Name "DisableClickToDo" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $devicePath -Name "DisableClickToDo" -Value 1 -Force
        } else {
            New-ItemProperty -Path $devicePath -Name "DisableClickToDo" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableClickToDo = 1 (Device-scope)" -Module "AntiAI"
        $result.Applied++
        
        # User-scope (HKCU)
        $userPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $userPath)) {
            New-Item -Path $userPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $userPath" -Module "AntiAI"
        }
        
        $existing = Get-ItemProperty -Path $userPath -Name "DisableClickToDo" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $userPath -Name "DisableClickToDo" -Value 1 -Force
        } else {
            New-ItemProperty -Path $userPath -Name "DisableClickToDo" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableClickToDo = 1 (User-scope)" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $deviceValues = Get-ItemProperty -Path $devicePath -ErrorAction SilentlyContinue
        $userValues = Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue
        
        $verified = ($deviceValues.DisableClickToDo -eq 1) -and
                   ($userValues.DisableClickToDo -eq 1)
        
        if ($verified) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: Click to Do disabled" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Click to Do policy not applied correctly"
        }
    }
    catch {
        $result.Errors += "Failed to disable Click to Do: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
