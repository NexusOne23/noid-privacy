#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Verifies that all AntiAI policies are correctly applied.

.DESCRIPTION
    REGISTRY COMPLIANCE VERIFICATION (Self-Check + MS Policy Validation)
    
    This script performs TWO types of checks:
    
    A) SELF-CHECK (Primary):
       Verifies that AntiAI module successfully set all intended registry keys:
       - Generative AI Master Switch (LetAppsAccessSystemAIModels)
       - Recall Core (AllowRecallEnablement, DisableAIDataAnalysis x2, DisableRecallDataProviders)
       - Recall Protection (App/URI Deny Lists, Storage Duration/Space)
       - Copilot (4-layer defense: WindowsAI, WindowsCopilot, ShowCopilotButton, Explorer, User-scope, Hardware Key)
       - Click to Do (DisableClickToDo x2)
       - Paint AI (DisableCocreator, DisableGenerativeFill, DisableImageCreator)
       - Notepad AI (DisableAIFeatures)
       - Settings Agent (DisableSettingsAgent)
    
    B) MS POLICY VALIDATION (Secondary):
       Checks for additional Microsoft-official registry keys that AntiAI module does NOT set,
       but which could indicate incomplete deactivation or MS policy changes:
       - PolicyManager paths (alternative policy enforcement)
       - Additional WindowsAI keys introduced in newer Windows builds
       - Alternative Copilot/Recall paths
    
    IMPORTANT LIMITATIONS:
    - This is a REGISTRY-ONLY check. It does NOT verify if AI features are functionally disabled.
    - "PASS" means "registry keys are set correctly" NOT "AI features are 100% inactive".
    - Microsoft may add new AI features or change registry paths in future Windows updates.
    - Some AI features may still work via cloud APIs even with correct registry settings.
    
    For functional verification, test AI features manually after applying policies.

.EXAMPLE
    .\Test-AntiAICompliance.ps1
    Runs full compliance check and displays results.

.NOTES
    Author: NoID Privacy
    Version: 2.2.2 (Extended validation)
    Requires: Windows 11 24H2+, Administrator privileges
#>

# Helper function to check registry value (must be outside main function)
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue,
        [string]$Description
    )
    
    $check = @{
        Description = $Description
        Path = "$Path\$Name"
        Expected = $ExpectedValue
        Actual = $null
        Status = "FAIL"
    }
    
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                $check.Actual = $value.$Name
                
                # Handle different value types
                if ($ExpectedValue -is [array]) {
                    # MultiString comparison - verify arrays match
                    if ($check.Actual -is [array]) {
                        # Check if arrays have same length and all items match
                        if ($check.Actual.Count -eq $ExpectedValue.Count) {
                            $allMatch = $true
                            foreach ($expectedItem in $ExpectedValue) {
                                if ($check.Actual -notcontains $expectedItem) {
                                    $allMatch = $false
                                    break
                                }
                            }
                            $check.Status = if ($allMatch) { "PASS" } else { "FAIL" }
                        }
                        else {
                            # Different array lengths - still OK if all expected items are present
                            # (allows for extra items set by policy)
                            $allPresent = $true
                            foreach ($expectedItem in $ExpectedValue) {
                                if ($check.Actual -notcontains $expectedItem) {
                                    $allPresent = $false
                                    break
                                }
                            }
                            $check.Status = if ($allPresent) { "PASS" } else { "FAIL" }
                        }
                    }
                    else {
                        # Expected array but got single value or nothing
                        $check.Status = "FAIL"
                    }
                }
                else {
                    # Exact value comparison
                    $check.Status = if ($check.Actual -eq $ExpectedValue) { "PASS" } else { "FAIL" }
                }
            }
            else {
                $check.Actual = "NOT SET"
            }
        }
        else {
            $check.Actual = "PATH MISSING"
        }
    }
    catch {
        $check.Actual = "ERROR: $($_.Exception.Message)"
    }
    
    return $check
}

function Test-AntiAICompliance {
    [CmdletBinding()]
    param()
    
    $startTime = Get-Date
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  ANTIAI COMPLIANCE VERIFICATION v2.2" -ForegroundColor Cyan
    Write-Host "  Registry-Based Policy Check" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Checking 32 AI Deactivation Policies" -ForegroundColor Cyan
    Write-Host "  + Advanced Copilot Blocks + MS Validation" -ForegroundColor DarkGray
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Initialize results (TotalPolicies calculated dynamically)
    $results = @{
        Passed = 0
        Failed = 0
        Warnings = 0
        Details = @()
        MSConflicts = 0
        MSAligned = 0
    }

Write-Host "[1/13] Checking Generative AI Master Switch..." -ForegroundColor Yellow
$check = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsAccessSystemAIModels" `
    -ExpectedValue 2 `
    -Description "Generative AI Master (Force Deny all apps)"
$results.Details += $check
if ($check.Status -eq "PASS") {
    Write-Host "  PASS: Master switch blocks all generative AI" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: Expected 2 (Force Deny), got $($check.Actual)" -ForegroundColor Red
    $results.Failed++
}

# Additional check for LetAppsAccessGenerativeAI (Text & Image Generation in Settings)
$genAICheck = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
    -Name "LetAppsAccessGenerativeAI" `
    -ExpectedValue 2 `
    -Description "Generative AI App Access (Force Deny)"
$results.Details += $genAICheck
if ($genAICheck.Status -eq "PASS") {
    Write-Host "  PASS: App access to generative AI blocked" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: LetAppsAccessGenerativeAI not set (may allow AI features)" -ForegroundColor Red
    $results.Failed++
}

# Additional CapabilityAccessManager check (workaround for Paint Generative Erase/Background Removal)
$capCheck = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" `
    -Name "Value" `
    -ExpectedValue "Deny" `
    -Description "CapabilityAccessManager systemAIModels (Workaround)"
$results.Details += $capCheck
if ($capCheck.Status -eq "PASS") {
    Write-Host "  PASS: CapabilityAccessManager blocks AI capabilities" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: CapabilityAccessManager not set (may allow Paint Generative Erase/Background Removal)" -ForegroundColor Red
    $results.Failed++
}

Write-Host "`n[2/13] Checking Recall Core Policies..." -ForegroundColor Yellow
$recallChecks = @(
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "AllowRecallEnablement" -ExpectedValue 0 -Description "Recall Component Removal"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ExpectedValue 1 -Description "Recall Snapshots Disabled (Device)"),
    (Test-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ExpectedValue 1 -Description "Recall Snapshots Disabled (User)"),
    (Test-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableRecallDataProviders" -ExpectedValue 1 -Description "Recall Data Providers Disabled")
)
foreach ($check in $recallChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  FAIL: $($check.Description) - $($check.Actual)" -ForegroundColor Red
        $results.Failed++
    }
}

Write-Host "`n[3/13] Checking Recall Enterprise Protection..." -ForegroundColor Yellow
# Expected deny lists (must match Set-RecallProtection.ps1)
$expectedDenyApps = @(
    "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!App",
    "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App",
    "KeePassXC_8wekyb3d8bbwe!KeePassXC",
    "Microsoft.RemoteDesktop_8wekyb3d8bbwe!App"
)
$expectedDenyUris = @(
    "*.bank.*",
    "*.paypal.*",
    "*.bankofamerica.*",
    "mail.*",
    "webmail.*",
    "*password*",
    "*login*"
)

$protectionChecks = @(
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "SetDenyAppListForRecall" -ExpectedValue $expectedDenyApps -Description "App Deny List"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "SetDenyUriListForRecall" -ExpectedValue $expectedDenyUris -Description "URI Deny List"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "SetMaximumStorageDurationForRecallSnapshots" -ExpectedValue 30 -Description "Max Retention: 30 days"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "SetMaximumStorageSpaceForRecallSnapshots" -ExpectedValue 10 -Description "Max Storage: 10 GB")
)
foreach ($check in $protectionChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  WARN: $($check.Description) - $($check.Actual)" -ForegroundColor Yellow
        $results.Warnings++
    }
}

Write-Host "`n[4/13] Checking Windows Copilot (4-layer defense)..." -ForegroundColor Yellow
$copilotChecks = @(
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "TurnOffWindowsCopilot" -ExpectedValue 1 -Description "Copilot Layer 1 (WindowsAI HKLM)"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ExpectedValue 1 -Description "Copilot Layer 2 (WindowsCopilot HKLM)"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "ShowCopilotButton" -ExpectedValue 0 -Description "Copilot Layer 3 (Taskbar Button Hidden)"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableWindowsCopilot" -ExpectedValue 1 -Description "Copilot Layer 4 (Explorer Integration)"),
    (Test-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -ExpectedValue 1 -Description "Copilot User-scope (HKCU)"),
    (Test-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "ShowCopilotButton" -ExpectedValue 0 -Description "Copilot Button Hidden (User)"),
    (Test-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "SetCopilotHardwareKey" -ExpectedValue "Microsoft.WindowsNotepad_8wekyb3d8bbwe!App" -Description "Hardware Key Remapped to Notepad")
)
foreach ($check in $copilotChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  FAIL: $($check.Description) - $($check.Actual)" -ForegroundColor Red
        $results.Failed++
    }
}

Write-Host "`n[5/13] Checking Click to Do..." -ForegroundColor Yellow
$clickChecks = @(
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableClickToDo" -ExpectedValue 1 -Description "Click to Do Disabled (Device)"),
    (Test-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableClickToDo" -ExpectedValue 1 -Description "Click to Do Disabled (User)")
)
foreach ($check in $clickChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  FAIL: $($check.Description) - $($check.Actual)" -ForegroundColor Red
        $results.Failed++
    }
}

Write-Host "`n[6/13] Checking Paint AI..." -ForegroundColor Yellow
$paintChecks = @(
    (Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint" -Name "DisableCocreator" -ExpectedValue 1 -Description "Paint Cocreator Disabled"),
    (Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint" -Name "DisableGenerativeFill" -ExpectedValue 1 -Description "Paint Generative Fill Disabled"),
    (Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint" -Name "DisableImageCreator" -ExpectedValue 1 -Description "Paint Image Creator Disabled")
)
foreach ($check in $paintChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  FAIL: $($check.Description) - $($check.Actual)" -ForegroundColor Red
        $results.Failed++
    }
}

Write-Host "`n[7/13] Checking Notepad AI..." -ForegroundColor Yellow
$check = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\WindowsNotepad" `
    -Name "DisableAIFeatures" `
    -ExpectedValue 1 `
    -Description "Notepad AI Disabled (Write/Summarize/Rewrite)"
$results.Details += $check
if ($check.Status -eq "PASS") {
    Write-Host "  PASS: Notepad AI completely disabled" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: Expected 1, got $($check.Actual)" -ForegroundColor Red
    $results.Failed++
}

Write-Host "`n[8/13] Checking Settings Agent..." -ForegroundColor Yellow
$check = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" `
    -Name "DisableSettingsAgent" `
    -ExpectedValue 1 `
    -Description "Settings AI Agent Disabled"
$results.Details += $check
if ($check.Status -eq "PASS") {
    Write-Host "  PASS: Settings Agent disabled (classic search only)" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: Expected 1, got $($check.Actual)" -ForegroundColor Red
    $results.Failed++
}

Write-Host "`n[9/13] Checking Explorer AI Actions..." -ForegroundColor Yellow
$check = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -Name "HideAIActionsMenu" `
    -ExpectedValue 1 `
    -Description "Explorer AI Actions Hidden"
$results.Details += $check
if ($check.Status -eq "PASS") {
    Write-Host "  PASS: Explorer AI Actions menu hidden" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  FAIL: Expected 1, got $($check.Actual)" -ForegroundColor Red
    $results.Failed++
}

Write-Host "`n[10/13] Checking Recall Export Block (NEW)..." -ForegroundColor Yellow
$check = Test-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" `
    -Name "AllowRecallExport" `
    -ExpectedValue 0 `
    -Description "Recall Export Disabled"
$results.Details += $check
if ($check.Status -eq "PASS") {
    Write-Host "  PASS: Recall snapshot export blocked" -ForegroundColor Green
    $results.Passed++
}
else {
    Write-Host "  WARN: Recall export may be allowed (optional policy)" -ForegroundColor Yellow
    $results.Warnings++
}

Write-Host "`n[11/13] Checking Edge Copilot Sidebar..." -ForegroundColor Yellow
$edgeCopilotChecks = @(
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeSidebarEnabled" -ExpectedValue 0 -Description "Edge Sidebar Disabled"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowHubsSidebar" -ExpectedValue 0 -Description "Hubs Sidebar Hidden"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -ExpectedValue 0 -Description "Hubs Sidebar Disabled"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CopilotPageContext" -ExpectedValue 0 -Description "Copilot Page Context Blocked"),
    (Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CopilotCDPPageContext" -ExpectedValue 0 -Description "Copilot CDP Context Blocked")
)
foreach ($check in $edgeCopilotChecks) {
    $results.Details += $check
    if ($check.Status -eq "PASS") {
        Write-Host "  PASS: $($check.Description)" -ForegroundColor Green
        $results.Passed++
    }
    else {
        Write-Host "  WARN: $($check.Description) - $($check.Actual)" -ForegroundColor Yellow
        $results.Warnings++
    }
}

Write-Host "`n[12/13] Checking Recall Component Status..." -ForegroundColor Yellow

# Check for Recall component status (Windows Optional Feature)
try {
    $recallFeature = Get-WindowsOptionalFeature -Online -FeatureName "Recall" -ErrorAction SilentlyContinue
    if ($null -ne $recallFeature) {
        if ($recallFeature.State -eq "Disabled") {
            Write-Host "  PASS: Recall component is disabled" -ForegroundColor Green
        }
        else {
            Write-Host "  INFO: Recall component present but configured to be removed (reboot required)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  PASS: Recall component not present on this system" -ForegroundColor Green
    }
}
catch {
    Write-Host "  INFO: Cannot query Recall feature status" -ForegroundColor DarkGray
}

Write-Host "`n[13/13] Checking MS Policy Validation (Conflict Scanner)..." -ForegroundColor Yellow

$msConflicts = 0
$msInfo = 0

try {
    # PolicyManager paths (alternative policy enforcement used by Intune/MDM)
    $policyManagerChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsAI"; Name = "DisableAIDataAnalysis"; Desc = "Recall PolicyManager (MDM Current)" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI"; Name = "DisableAIDataAnalysis"; Desc = "Recall PolicyManager (MDM Default)" }
    )
    
    foreach ($check in $policyManagerChecks) {
        try {
            if (Test-Path $check.Path) {
                $prop = Get-ItemProperty -Path $check.Path -ErrorAction SilentlyContinue
                if ($prop -and ($prop.PSObject.Properties.Name -contains $check.Name)) {
                    $value = $prop.($check.Name)
                    if ($null -ne $value) {
                        if ($value -eq 1) {
                            Write-Host "    INFO: $($check.Desc) = 1 (aligned with AntiAI)" -ForegroundColor DarkGray
                            $msInfo++
                        }
                        else {
                            Write-Host "    WARN: $($check.Desc) = $value (may conflict with AntiAI!)" -ForegroundColor Yellow
                            $msConflicts++
                        }
                    }
                }
            }
        }
        catch {
            # Silently ignore if property doesn't exist or path is inaccessible
            $null = $null
        }
    }
    
    # Check for alternative Copilot/Explorer keys (conflict detection)
    $additionalMSKeys = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoCopilotButton"; ExpectedValue = 1; Desc = "Explorer Copilot Button" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "CopilotPageEnabled"; ExpectedValue = 0; Desc = "Edge Copilot Integration" }
    )
    
    foreach ($check in $additionalMSKeys) {
        try {
            if (Test-Path $check.Path) {
                $prop = Get-ItemProperty -Path $check.Path -ErrorAction SilentlyContinue
                if ($prop -and ($prop.PSObject.Properties.Name -contains $check.Name)) {
                    $value = $prop.($check.Name)
                    if ($null -ne $value) {
                        if ($value -eq $check.ExpectedValue) {
                            Write-Host "    INFO: $($check.Desc) = $value (aligned with AntiAI)" -ForegroundColor DarkGray
                            $msInfo++
                        }
                        else {
                            Write-Host "    WARN: $($check.Desc) = $value (may conflict with AntiAI, expected $($check.ExpectedValue))" -ForegroundColor Yellow
                            $msConflicts++
                        }
                    }
                }
            }
        }
        catch {
            # Silently ignore if property doesn't exist or path is inaccessible
            $null = $null
        }
    }
    
    if ($msConflicts -eq 0 -and $msInfo -eq 0) {
        Write-Host "    No alternative MS policies detected (clean configuration)" -ForegroundColor DarkGray
    }
    elseif ($msConflicts -gt 0) {
        Write-Host "    CONFLICTS DETECTED: $msConflicts MS policy conflict(s) found!" -ForegroundColor Yellow
    }
    else {
        Write-Host "    $msInfo additional MS policy/policies aligned with AntiAI" -ForegroundColor DarkGray
    }
    
    Write-Host "    NOTE: MS Policy Validation scans for conflicts with AntiAI configuration." -ForegroundColor DarkGray
    Write-Host "          Missing keys are OK - conflicts are reported as warnings." -ForegroundColor DarkGray
}
catch {
    Write-Host "    WARNING: MS Policy Validation encountered an error: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    Continuing with self-check results only..." -ForegroundColor DarkGray
}

# Store MS validation results
$results.MSConflicts = $msConflicts
$results.MSAligned = $msInfo

# Calculate final results
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

# TotalPolicies = Passed + Failed (Warnings are informational only)
$totalPolicies = $results.Passed + $results.Failed

if ($totalPolicies -gt 0) {
    $successRate = [math]::Round(($results.Passed / $totalPolicies) * 100, 1)
}
else {
    $successRate = 0
}

# Derive overall status for programmatic use
if ($results.Failed -eq 0 -and $results.Passed -gt 0) {
    # All checks passed (warnings are OK)
    $overallStatus = "PASS"
}
elseif ($results.Passed -eq 0 -and $results.Failed -gt 0) {
    # All checks failed - likely AntiAI module was never run
    $overallStatus = "NOT_APPLIED"
}
elseif ($results.Failed -gt 0) {
    # Some checks failed
    $overallStatus = "FAIL"
}
else {
    # Edge case: no checks run
    $overallStatus = "NOT_APPLIED"
}

$results["OverallStatus"] = $overallStatus
$results["TotalPolicies"] = $totalPolicies
$results["TotalChecks"] = $totalPolicies
$results["FailedChecks"] = $results.Failed
$results["DurationSeconds"] = [math]::Round($duration, 2)

# Set exit code for programmatic use
# 0 = All checks passed, no MS conflicts
# 1 = Self-check failed (AntiAI policies not set correctly)
# 2 = Self-check passed but MS conflicts detected
$exitCode = 0
if ($results.Failed -gt 0) {
    $exitCode = 1
}
elseif ($results.MSConflicts -gt 0) {
    $exitCode = 2
}
$results["ExitCode"] = $exitCode

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  COMPLIANCE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Self-Check Results
Write-Host "Self-Check (AntiAI Policies):" -ForegroundColor Cyan
Write-Host "  Total Policies:    $totalPolicies" -ForegroundColor White
Write-Host "  Passed:            " -NoNewline
Write-Host "$($results.Passed)" -ForegroundColor Green
Write-Host "  Failed:            " -NoNewline
if ($results.Failed -eq 0) {
    Write-Host "$($results.Failed)" -ForegroundColor Green
}
else {
    Write-Host "$($results.Failed)" -ForegroundColor Red
}
Write-Host "  Warnings:          " -NoNewline
if ($results.Warnings -eq 0) {
    Write-Host "$($results.Warnings)" -ForegroundColor Green
}
else {
    Write-Host "$($results.Warnings)" -ForegroundColor Yellow
}
Write-Host "  Success Rate:      " -NoNewline
if ($successRate -eq 100) {
    Write-Host "$successRate%" -ForegroundColor Green
}
elseif ($successRate -ge 80) {
    Write-Host "$successRate%" -ForegroundColor Yellow
}
else {
    Write-Host "$successRate%" -ForegroundColor Red
}

# MS Policy Validation Results
Write-Host "`nMS Policy Validation:" -ForegroundColor Cyan
Write-Host "  Conflicts:         " -NoNewline
if ($results.MSConflicts -eq 0) {
    Write-Host "$($results.MSConflicts)" -ForegroundColor Green
}
else {
    Write-Host "$($results.MSConflicts)" -ForegroundColor Yellow
}
Write-Host "  Aligned:           $($results.MSAligned)" -ForegroundColor White
Write-Host "  Status:            " -NoNewline
if ($results.MSConflicts -eq 0) {
    Write-Host "NO CONFLICTS" -ForegroundColor Green
}
else {
    Write-Host "CONFLICTS DETECTED" -ForegroundColor Yellow
}

Write-Host "`nExecution:" -ForegroundColor Cyan
Write-Host "  Duration:          $([math]::Round($duration, 2)) seconds" -ForegroundColor White

Write-Host "`nOverall Status:    " -NoNewline
switch ($overallStatus) {
    "PASS" {
        if ($results.MSConflicts -eq 0) {
            Write-Host "COMPLIANT - All checks passed, no conflicts (Exit Code: 0)" -ForegroundColor Green
        }
        else {
            Write-Host "COMPLIANT - Registry OK, but MS conflicts detected (Exit Code: 2)" -ForegroundColor Yellow
        }
    }
    "NOT_APPLIED" {
        Write-Host "NOT APPLIED - AntiAI module has not been run yet (Exit Code: 1)" -ForegroundColor Yellow
    }
    default {
        Write-Host "NON-COMPLIANT - Action required (Exit Code: 1)" -ForegroundColor Red
    }
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# IMPORTANT DISCLAIMER
if ($overallStatus -eq "PASS") {
    Write-Host "  IMPORTANT: This check verifies REGISTRY COMPLIANCE ONLY." -ForegroundColor Yellow
    Write-Host "  It does NOT guarantee that AI features are functionally disabled." -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "  Reasons why AI features might still work:" -ForegroundColor DarkGray
    Write-Host "    - Microsoft may use alternative/undocumented registry paths" -ForegroundColor DarkGray
    Write-Host "    - Cloud-based AI features bypass local policies" -ForegroundColor DarkGray
    Write-Host "    - Newer Windows builds may introduce new AI keys/features" -ForegroundColor DarkGray
    Write-Host "    - Apps may have hardcoded AI functionality" -ForegroundColor DarkGray
    Write-Host "" -ForegroundColor Yellow
    Write-Host "  RECOMMENDATION: Manually test AI features after applying policies:" -ForegroundColor Yellow
    Write-Host "    - Open Notepad -> Check for AI/Copilot button" -ForegroundColor DarkGray
    Write-Host "    - Open Paint -> Check for Cocreator/Generative Fill" -ForegroundColor DarkGray
    Write-Host "    - Press Win+C -> Should NOT open Copilot" -ForegroundColor DarkGray
    Write-Host "    - Snipping Tool -> Check for AI OCR/Redact features" -ForegroundColor DarkGray
    Write-Host "`n========================================`n" -ForegroundColor Cyan
}
    
    # Return results object
    return $results
}
