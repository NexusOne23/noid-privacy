#Requires -Version 5.1

<#
.SYNOPSIS
    Disables all AI features in Paint (Cocreator, Generative Fill, Image Creator).

.DESCRIPTION
    Applies 3 Paint AI policies:
    1. DisableCocreator = 1 (Text-to-image generation)
    2. DisableGenerativeFill = 1 (AI-powered content-aware fill)
    3. DisableImageCreator = 1 (DALL-E art generator)
    
    Paint AI features (cloud-based):
    - Cocreator: Type description, AI generates artwork (e.g., "sunset over mountains")
    - Generative Fill: Select area, AI fills with contextual content
    - Image Creator: DALL-E powered AI art generation
    
    All features require internet connection and send data to Microsoft cloud.

.EXAMPLE
    Disable-PaintAI
#>
function Disable-PaintAI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Paint AI features (Cocreator, Generative Fill, Image Creator)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Paint AI (Cocreator, GenerativeFill, ImageCreator)" -Module "AntiAI"
            $result.Applied += 3
            $result.Success = $true
            return $result
        }
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        # 1. Disable Cocreator (text-to-image)
        $existing = Get-ItemProperty -Path $regPath -Name "DisableCocreator" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "DisableCocreator" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "DisableCocreator" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableCocreator = 1 (Text-to-image generation disabled)" -Module "AntiAI"
        $result.Applied++
        
        # 2. Disable Generative Fill (AI content-aware fill)
        $existing = Get-ItemProperty -Path $regPath -Name "DisableGenerativeFill" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "DisableGenerativeFill" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "DisableGenerativeFill" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableGenerativeFill = 1 (AI content-aware fill disabled)" -Module "AntiAI"
        $result.Applied++
        
        # 3. Disable Image Creator (DALL-E art generator)
        $existing = Get-ItemProperty -Path $regPath -Name "DisableImageCreator" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "DisableImageCreator" -Value 1 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "DisableImageCreator" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableImageCreator = 1 (DALL-E art generation disabled)" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        $verified = ($values.DisableCocreator -eq 1) -and
                   ($values.DisableGenerativeFill -eq 1) -and
                   ($values.DisableImageCreator -eq 1)
        
        if ($verified) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: All Paint AI features disabled" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Not all Paint AI policies were applied"
        }
    }
    catch {
        $result.Errors += "Failed to disable Paint AI: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
