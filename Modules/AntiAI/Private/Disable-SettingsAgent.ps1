#Requires -Version 5.1

<#
.SYNOPSIS
    Disables Settings Agent (AI-powered Settings search).

.DESCRIPTION
    Applies DisableSettingsAgent = 1 policy.
    
    Settings Agent provides AI-enhanced natural language search in Windows Settings.
    Examples of AI features:
    - Understanding questions: "How do I change my wallpaper?"
    - Contextual suggestions: "Change background" -> Desktop personalization
    - Intelligent search results with natural language processing
    
    Disabling falls back to classic keyword search without AI understanding.

.EXAMPLE
    Disable-SettingsAgent
#>
function Disable-SettingsAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Settings Agent (AI-powered search)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Settings Agent (DisableAISettingsAgent=1)" -Module "AntiAI"
            $result.Applied++
            $result.Success = $true
            return $result
        }
        
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        $existing = Get-ItemProperty -Path $regPath -Name "DisableSettingsAgent" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "DisableSettingsAgent" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "DisableSettingsAgent" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableSettingsAgent = 1 (AI search disabled, fallback to classic)" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        if ($values.DisableSettingsAgent -eq 1) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: Settings Agent disabled" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Settings Agent policy not applied"
        }
    }
    catch {
        $result.Errors += "Failed to disable Settings Agent: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
