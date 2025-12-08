#Requires -Version 5.1

<#
.SYNOPSIS
    Sets the Generative AI Master Switch to block all apps from using AI models.

.DESCRIPTION
    Configures LetAppsAccessSystemAIModels = 2 (Force Deny) to prevent ALL apps from
    accessing Windows on-device generative AI models (text and image generation).
    
    This master switch automatically blocks:
    - Notepad AI (Write, Summarize, Rewrite)
    - Paint AI (Cocreator, Generative Fill unless specifically disabled)
    - Photos AI (Generative Erase, Background effects, Auto-categorization)
    - Clipchamp AI (Auto Compose)
    - Snipping Tool AI (OCR, Quick Redact)
    - All future apps that use generative AI

.EXAMPLE
    Set-SystemAIModels
#>
function Set-SystemAIModels {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Setting Generative AI Master Switch (Force Deny all apps)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        # 1. Set AppPrivacy Master Switch
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would set $regPath\LetAppsAccessSystemAIModels = 2" -Module "AntiAI"
            Write-Log -Level DEBUG -Message "[DRYRUN] Would set $regPath\LetAppsAccessGenerativeAI = 2" -Module "AntiAI"
            Write-Log -Level DEBUG -Message "[DRYRUN] Would set CapabilityAccessManager\systemAIModels = Deny" -Module "AntiAI"
            $result.Success = $true
            return $result
        }
        
        # Ensure registry path exists
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        # Set master switch: 2 = Force Deny (no app can access generative AI)
        $existing = Get-ItemProperty -Path $regPath -Name "LetAppsAccessSystemAIModels" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "LetAppsAccessSystemAIModels" -Value 2 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "LetAppsAccessSystemAIModels" -Value 2 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set LetAppsAccessSystemAIModels = 2 (Force Deny)" -Module "AntiAI"
        $result.Applied++
        
        # Set app-level Generative AI access: 2 = Force Deny (Text & Image Generation in Settings)
        $existing2 = Get-ItemProperty -Path $regPath -Name "LetAppsAccessGenerativeAI" -ErrorAction SilentlyContinue
        if ($null -ne $existing2) {
            Set-ItemProperty -Path $regPath -Name "LetAppsAccessGenerativeAI" -Value 2 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "LetAppsAccessGenerativeAI" -Value 2 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set LetAppsAccessGenerativeAI = 2 (Force Deny)" -Module "AntiAI"
        $result.Applied++
        
        # Verify AppPrivacy switches
        $value = Get-ItemProperty -Path $regPath -Name "LetAppsAccessSystemAIModels" -ErrorAction SilentlyContinue
        $value2 = Get-ItemProperty -Path $regPath -Name "LetAppsAccessGenerativeAI" -ErrorAction SilentlyContinue
        if ($value.LetAppsAccessSystemAIModels -eq 2 -and $value2.LetAppsAccessGenerativeAI -eq 2) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: Both AppPrivacy AI switches are Force Deny" -Module "AntiAI"
        }
        else {
            $result.Errors += "Verification FAILED: AppPrivacy AI switches not set correctly"
        }
        
        # 2. Set CapabilityAccessManager Deny (additional workaround for Paint Generative Erase/Background Removal)
        $capabilityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels"
        
        if (-not (Test-Path $capabilityPath)) {
            New-Item -Path $capabilityPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $capabilityPath" -Module "AntiAI"
        }
        
        $existing = Get-ItemProperty -Path $capabilityPath -Name "Value" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $capabilityPath -Name "Value" -Value "Deny" -Force
        } else {
            New-ItemProperty -Path $capabilityPath -Name "Value" -Value "Deny" -PropertyType String -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set CapabilityAccessManager\systemAIModels = Deny (workaround for undocumented AI features)" -Module "AntiAI"
        $result.Applied++
        
        # Verify CapabilityAccessManager
        $capValue = Get-ItemProperty -Path $capabilityPath -Name "Value" -ErrorAction SilentlyContinue
        if ($capValue.Value -eq "Deny") {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: CapabilityAccessManager is Deny" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: CapabilityAccessManager not set correctly"
        }
    }
    catch {
        $result.Errors += "Failed to set Generative AI Master Switch: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
