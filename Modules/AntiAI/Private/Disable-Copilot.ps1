#Requires -Version 5.1

<#
.SYNOPSIS
    Disables Windows Copilot system-wide (App Removal + Multi-Layer Policies).

.DESCRIPTION
    Complete Copilot removal for Windows 11 24H2/25H2+:
    
    LAYER 0: APP REMOVAL (NEW - Windows 11 24H2/25H2+)
    - Removes Copilot AppX packages (current user, all users, provisioned)
    - Prevents Copilot integration in Paint, Office, and other apps
    - Microsoft Official: TurnOffWindowsCopilot policy is DEPRECATED in 24H2+
    - Reference: https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot
    
    LEGACY LAYERS (for older Windows 11 versions):
    - Layer 1-4: Registry policies (WindowsAI, WindowsCopilot, Explorer)
    - Layer 5: Hardware key remap to Notepad
    
    Multi-layer approach ensures maximum compatibility across all Windows 11 versions.

.PARAMETER DryRun
    Simulates the operation without making changes.

.EXAMPLE
    Disable-Copilot
    
.NOTES
    Requires Administrator privileges.
    Best Practice: Run with -Verbose to see detailed operation log.
#>
function Disable-Copilot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Windows Copilot (multi-layer defense + app removal)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
        CopilotAppRemoved = $false
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Copilot (app removal + policies + hardware key)" -Module "AntiAI"
            $result.Applied += 8  # 1 app removal + 2 HKLM policies + 1 ShowButton + 1 Explorer + 2 HKCU + 1 HW key
            $result.CopilotAppRemoved = $true
            $result.Success = $true
            return $result
        }
        
        # ============================================================================
        # LAYER 0: REMOVE COPILOT APP (Windows 11 24H2/25H2+)
        # ============================================================================
        # Microsoft official: TurnOffWindowsCopilot policy is DEPRECATED in 24H2+
        # New method: Uninstall Copilot app completely (prevents in-app integration)
        # Reference: https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot
        
        Write-Log -Level DEBUG -Message "Layer 0: Removing Copilot app packages..." -Module "AntiAI"
        
        # Step 1: Remove for current user
        $copilotPackages = Get-AppxPackage -Name "*Copilot*" -ErrorAction SilentlyContinue
        if ($copilotPackages) {
            foreach ($package in $copilotPackages) {
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
                    Write-Log -Level DEBUG -Message "Removed Copilot package: $($package.Name)" -Module "AntiAI"
                    $result.CopilotAppRemoved = $true
                }
                catch {
                    Write-Log -Level DEBUG -Message "Could not remove package $($package.Name): $($_.Exception.Message)" -Module "AntiAI"
                }
            }
        }
        
        # Step 2: Remove for all users (requires admin)
        $copilotAllUsers = Get-AppxPackage -AllUsers -Name "*Copilot*" -ErrorAction SilentlyContinue
        if ($copilotAllUsers) {
            foreach ($package in $copilotAllUsers) {
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Log -Level DEBUG -Message "Removed Copilot package (all users): $($package.Name)" -Module "AntiAI"
                    $result.CopilotAppRemoved = $true
                }
                catch {
                    Write-Log -Level DEBUG -Message "Could not remove package for all users: $($_.Exception.Message)" -Module "AntiAI"
                }
            }
        }
        
        # Step 3: Remove provisioned packages (prevents reinstall for new users)
        $provisionedCopilot = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                              Where-Object { $_.PackageName -like "*Copilot*" }
        if ($provisionedCopilot) {
            foreach ($package in $provisionedCopilot) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop | Out-Null
                    Write-Log -Level DEBUG -Message "Removed provisioned Copilot package: $($package.PackageName)" -Module "AntiAI"
                    $result.CopilotAppRemoved = $true
                }
                catch {
                    Write-Log -Level DEBUG -Message "Could not remove provisioned package: $($_.Exception.Message)" -Module "AntiAI"
                }
            }
        }
        
        if ($result.CopilotAppRemoved) {
            Write-Log -Level DEBUG -Message "Layer 0: Copilot app packages removed successfully" -Module "AntiAI"
            $result.Applied++
        }
        else {
            Write-Log -Level DEBUG -Message "Layer 0: No Copilot app packages found (already removed or not installed)" -Module "AntiAI"
        }
        
        # ============================================================================
        # LEGACY LAYERS: Registry policies (still needed for older Windows 11 versions)
        # ============================================================================
        
        # MULTI-LAYER COPILOT BLOCKING (SecurityBaseline Best Practice)
        
        # Layer 1: WindowsAI\TurnOffWindowsCopilot (HKLM - machine-wide)
        $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $aiPolicyPath)) {
            New-Item -Path $aiPolicyPath -Force | Out-Null
        }
        
        $existing = Get-ItemProperty -Path $aiPolicyPath -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $aiPolicyPath -Name "TurnOffWindowsCopilot" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $aiPolicyPath -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Layer 1: WindowsAI\TurnOffWindowsCopilot (HKLM) = 1" -Module "AntiAI"
        $result.Applied++
        
        # Layer 2: WindowsCopilot\TurnOffWindowsCopilot (HKLM - legacy path)
        $copilotPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        if (-not (Test-Path $copilotPathHKLM)) {
            New-Item -Path $copilotPathHKLM -Force | Out-Null
        }
        
        $existing = Get-ItemProperty -Path $copilotPathHKLM -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $copilotPathHKLM -Name "TurnOffWindowsCopilot" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $copilotPathHKLM -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Layer 2: WindowsCopilot\TurnOffWindowsCopilot (HKLM) = 1" -Module "AntiAI"
        $result.Applied++
        
        # Layer 3: ShowCopilotButton = 0 (Hide taskbar button)
        $existing = Get-ItemProperty -Path $copilotPathHKLM -Name "ShowCopilotButton" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $copilotPathHKLM -Name "ShowCopilotButton" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $copilotPathHKLM -Name "ShowCopilotButton" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Layer 3: ShowCopilotButton (HKLM) = 0" -Module "AntiAI"
        $result.Applied++
        
        # Layer 4: Explorer\DisableWindowsCopilot (Block Explorer integration)
        $explorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (-not (Test-Path $explorerPath)) {
            New-Item -Path $explorerPath -Force | Out-Null
        }
        
        $existing = Get-ItemProperty -Path $explorerPath -Name "DisableWindowsCopilot" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $explorerPath -Name "DisableWindowsCopilot" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $explorerPath -Name "DisableWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Layer 4: Explorer\DisableWindowsCopilot (HKLM) = 1" -Module "AntiAI"
        $result.Applied++
        
        # User-scope policies (HKCU - additional protection)
        $copilotPathHKCU = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
        if (-not (Test-Path $copilotPathHKCU)) {
            New-Item -Path $copilotPathHKCU -Force | Out-Null
        }
        
        $existing = Get-ItemProperty -Path $copilotPathHKCU -Name "TurnOffWindowsCopilot" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $copilotPathHKCU -Name "TurnOffWindowsCopilot" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $copilotPathHKCU -Name "TurnOffWindowsCopilot" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "User-scope: WindowsCopilot\TurnOffWindowsCopilot (HKCU) = 1" -Module "AntiAI"
        $result.Applied++
        
        $existing = Get-ItemProperty -Path $copilotPathHKCU -Name "ShowCopilotButton" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $copilotPathHKCU -Name "ShowCopilotButton" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $copilotPathHKCU -Name "ShowCopilotButton" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "User-scope: ShowCopilotButton (HKCU) = 0" -Module "AntiAI"
        $result.Applied++
        
        # Layer 5: Remap hardware Copilot key to Notepad (neutralize dedicated key)
        $aiPathHKCU = "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $aiPathHKCU)) {
            New-Item -Path $aiPathHKCU -Force | Out-Null
        }
        
        $notepadAUMID = "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App"
        $existing = Get-ItemProperty -Path $aiPathHKCU -Name "SetCopilotHardwareKey" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $aiPathHKCU -Name "SetCopilotHardwareKey" -Value $notepadAUMID -Force | Out-Null
        } else {
            New-ItemProperty -Path $aiPathHKCU -Name "SetCopilotHardwareKey" -Value $notepadAUMID -PropertyType String -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Layer 5: Hardware Copilot key remapped to Notepad" -Module "AntiAI"
        $result.Applied++
        
        # Verify all layers
        $aiHKLM = Get-ItemProperty -Path $aiPolicyPath -ErrorAction SilentlyContinue
        $copilotHKLM = Get-ItemProperty -Path $copilotPathHKLM -ErrorAction SilentlyContinue
        $explorerHKLM = Get-ItemProperty -Path $explorerPath -ErrorAction SilentlyContinue
        $copilotHKCU = Get-ItemProperty -Path $copilotPathHKCU -ErrorAction SilentlyContinue
        $aiHKCU = Get-ItemProperty -Path $aiPathHKCU -ErrorAction SilentlyContinue
        
        $verified = ($aiHKLM.TurnOffWindowsCopilot -eq 1) -and
                   ($copilotHKLM.TurnOffWindowsCopilot -eq 1) -and
                   ($copilotHKLM.ShowCopilotButton -eq 0) -and
                   ($explorerHKLM.DisableWindowsCopilot -eq 1) -and
                   ($copilotHKCU.TurnOffWindowsCopilot -eq 1) -and
                   ($copilotHKCU.ShowCopilotButton -eq 0) -and
                   ($aiHKCU.SetCopilotHardwareKey -eq $notepadAUMID)
        
        if ($verified) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: All Copilot policies configured (MS official keys only)" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Not all Copilot policies applied correctly"
        }
    }
    catch {
        $result.Errors += "Failed to disable Copilot: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
