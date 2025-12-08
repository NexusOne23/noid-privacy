#Requires -Version 5.1

<#
.SYNOPSIS
    Disables all AI features in Notepad (Write, Summarize, Rewrite, Explain).

.DESCRIPTION
    Applies DisableAIFeatures = 1 policy (Microsoft official registry value name).
    
    Notepad AI features (GPT-powered):
    - Write: Generate text from prompts
    - Summarize: Condense long text into key points
    - Rewrite: Rephrase text in different styles (formal, casual, professional)
    - Explain: Clarify complex text
    
    All features are cloud-based and require Copilot integration.
    
    WARNING: Requires WindowsNotepad.admx for Group Policy (not required for direct registry).
    ADMX Download: https://download.microsoft.com/download/72ea16a9-4cc9-4032-945d-3a56a483d034/WindowsNotepadAdminTemplates.cab

.EXAMPLE
    Disable-NotepadAI
#>
function Disable-NotepadAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Notepad AI features (Write, Summarize, Rewrite, Explain)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
        Warnings = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Notepad AI (DisableAIFeatures=1)" -Module "AntiAI"
            $result.Applied++
            $result.Success = $true
            return $result
        }
        
        $regPath = "HKLM:\SOFTWARE\Policies\WindowsNotepad"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        # CRITICAL: Value name is "DisableAIFeatures" (NOT "DisableAIFeaturesInNotepad")
        # Microsoft official registry value name from WindowsNotepad ADMX
        $existing = Get-ItemProperty -Path $regPath -Name "DisableAIFeatures" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "DisableAIFeatures" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "DisableAIFeatures" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableAIFeatures = 1 (All AI features disabled - Write/Summarize/Rewrite/Explain)" -Module "AntiAI"
        $result.Applied++
        
        # Note: WindowsNotepad.admx is NOT required - registry policy is fully effective without it
        # ADMX only provides GUI visibility in gpedit.msc, which is irrelevant for scripted deployment
        Write-Log -Level DEBUG -Message "Notepad AI disabled via registry policy (no ADMX required)" -Module "AntiAI"
        
        # Verify with correct value name
        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        if ($values.DisableAIFeatures -eq 1) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: Notepad AI disabled (DisableAIFeatures=1)" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Notepad AI policy not applied (DisableAIFeatures not set)"
        }
    }
    catch {
        $result.Errors += "Failed to disable Notepad AI: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
