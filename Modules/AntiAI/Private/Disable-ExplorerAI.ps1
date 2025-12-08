#Requires -Version 5.1

<#
.SYNOPSIS
    Disables AI Actions in File Explorer context menu.

.DESCRIPTION
    Applies HideAIActionsMenu = 1 policy.
    
    File Explorer AI Actions provides AI-powered features in the right-click menu:
    - Image editing with AI (background removal, effects)
    - Text summarization
    - AI-powered file actions
    
    Disabling removes the "AI Actions" entry from the File Explorer context menu.

.EXAMPLE
    Disable-ExplorerAI
#>
function Disable-ExplorerAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling File Explorer AI Actions Menu" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Explorer AI Actions (HideAIActionsMenu=1)" -Module "AntiAI"
            $result.Applied++
            $result.Success = $true
            return $result
        }
        
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        $existing = Get-ItemProperty -Path $regPath -Name "HideAIActionsMenu" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "HideAIActionsMenu" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "HideAIActionsMenu" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set HideAIActionsMenu = 1 (AI Actions hidden from Explorer context menu)" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        if ($values.HideAIActionsMenu -eq 1) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: Explorer AI Actions disabled" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Explorer AI Actions policy not applied"
        }
    }
    catch {
        $result.Errors += "Failed to disable Explorer AI Actions: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
