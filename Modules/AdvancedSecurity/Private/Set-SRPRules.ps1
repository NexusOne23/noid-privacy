function Set-SRPRules {
    <#
    .SYNOPSIS
        Configures Software Restriction Policies (SRP) to block .lnk execution from Temp/Downloads

    .DESCRIPTION
        Configures two legacy SRP path rules as defense-in-depth against launching
        .lnk files directly from Temp and Downloads. Microsoft deprecated SRP
        beginning with Windows 10 1803 and recommends WDAC or AppLocker; registry
        readback proves configuration, not runtime enforcement.

        DEFENSE-IN-DEPTH (path-based LNK execution control):
        - CVE-2025-9491 (ZDI-CAN-25373): Windows LNK UI-misrepresentation,
          exploited since 2017 by multiple state-sponsored groups.
        - These legacy path rules are an additional location-based restriction;
          they are not claimed as a complete CVE mitigation.

        SRP Rules Created:
        1. Block *.lnk from %LOCALAPPDATA%\Temp\* (Outlook attachments)
        2. Block *.lnk from %USERPROFILE%\Downloads\* (Browser downloads)

    .PARAMETER DryRun
        Preview changes without applying them

    .EXAMPLE
        Set-SRPRules
        Applies SRP rules to block malicious .lnk execution

    .NOTES
        Author: NexusOne23
        Version: 2.2.5
        Requires: Administrator privileges

        REFERENCES:
        - Microsoft advisory: https://msrc.microsoft.com/update-guide/advisory/ADV25258226
        - SRP status: https://learn.microsoft.com/windows-server/identity/software-restriction-policies/software-restriction-policies
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set SRPRules')) {
        return
    }


    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\SRP-Rules.json"

        if (-not (Test-Path $configPath)) {
            Write-Log -Level ERROR -Message "SRP-Rules.json not found: $configPath" -Module "AdvancedSecurity"
            return $false
        }

        $config = Get-Content $configPath -Raw | ConvertFrom-Json

        Write-Log -Level INFO -Message "Configuring Software Restriction Policies (SRP) for CVE-2025-9491..." -Module "AdvancedSecurity"

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure SRP with following rules:" -Module "AdvancedSecurity"
            foreach ($rule in $config.PathRules) {
                Write-Log -Level INFO -Message "[DRYRUN]   - $($rule.Name): $($rule.Path)" -Module "AdvancedSecurity"
            }
            return $true
        }

        # Step 1: Create SRP Policy Root. Its exact targeted pre-state was
        # sealed before Apply.
        $policyRoot = $config.RegistryPaths.PolicyRoot

        if (-not (Test-Path $policyRoot)) {
            Write-Log -Level INFO -Message "Creating SRP policy root: $policyRoot" -Module "AdvancedSecurity"
            New-Item -Path $policyRoot -Force -ErrorAction Stop | Out-Null
        }

        # Step 2: Set Default Level (Unrestricted)
        Write-Log -Level INFO -Message "Setting SRP default level to Unrestricted (262144)" -Module "AdvancedSecurity"

        Remove-ItemProperty -LiteralPath $policyRoot -Name 'DefaultLevel' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $policyRoot -Name 'DefaultLevel' -Value ([int]$config.SRPConfiguration.DefaultLevel) -PropertyType DWord -Force -ErrorAction Stop | Out-Null

        # Step 3: Enable Transparent Enforcement
        Remove-ItemProperty -LiteralPath $policyRoot -Name 'TransparentEnabled' -ErrorAction SilentlyContinue
        New-ItemProperty -Path $policyRoot -Name 'TransparentEnabled' -Value ([int]$config.SRPConfiguration.TransparentEnabled) -PropertyType DWord -Force -ErrorAction Stop | Out-Null

        # Step 4: Create Path Rules
        $pathRulesRoot = $config.RegistryPaths.PathRules

        if (-not (Test-Path $pathRulesRoot)) {
            Write-Log -Level INFO -Message "Creating SRP path rules root: $pathRulesRoot" -Module "AdvancedSecurity"
            New-Item -Path $pathRulesRoot -Force -ErrorAction Stop | Out-Null
        }

        $rulesCreated = 0

        foreach ($rule in $config.PathRules) {
            if (-not $rule.Enabled) {
                Write-Log -Level INFO -Message "Skipping disabled rule: $($rule.Name)" -Module "AdvancedSecurity"
                continue
            }

            # Stable IDs make ownership and exact rollback deterministic.
            if ([string]::IsNullOrWhiteSpace([string]$rule.Id) -or [string]$rule.Id -notmatch '^\{[0-9A-Fa-f-]{36}\}$') {
                throw "SRP rule '$($rule.Name)' has no valid stable Id"
            }
            $rulePath = Join-Path $pathRulesRoot ([string]$rule.Id)

            Write-Log -Level INFO -Message "Creating SRP rule: $($rule.Name)" -Module "AdvancedSecurity"

            if (-not (Test-Path $rulePath)) {
                New-Item -Path $rulePath -Force -ErrorAction Stop | Out-Null
            }

            # Set ItemData (path pattern)
            Remove-ItemProperty -LiteralPath $rulePath -Name 'ItemData' -ErrorAction SilentlyContinue
            New-ItemProperty -Path $rulePath -Name 'ItemData' -Value ([string]$rule.Path) -PropertyType ExpandString -Force -ErrorAction Stop | Out-Null

            # Set Description
            Remove-ItemProperty -LiteralPath $rulePath -Name 'Description' -ErrorAction SilentlyContinue
            New-ItemProperty -Path $rulePath -Name 'Description' -Value ([string]$rule.Description) -PropertyType String -Force -ErrorAction Stop | Out-Null

            # Set SaferFlags
            Remove-ItemProperty -LiteralPath $rulePath -Name 'SaferFlags' -ErrorAction SilentlyContinue
            New-ItemProperty -Path $rulePath -Name 'SaferFlags' -Value ([int]$rule.SaferFlags) -PropertyType DWord -Force -ErrorAction Stop | Out-Null

            $rulesCreated++
            Write-Log -Level SUCCESS -Message "SRP rule created: $($rule.Name) -> $($rule.Path)" -Module "AdvancedSecurity"
        }

        $policyKey = Get-Item -LiteralPath $policyRoot -ErrorAction Stop
        if ($policyKey.GetValueKind('DefaultLevel').ToString() -ne 'DWord' -or
            [int]$policyKey.GetValue('DefaultLevel') -ne [int]$config.SRPConfiguration.DefaultLevel -or
            $policyKey.GetValueKind('TransparentEnabled').ToString() -ne 'DWord' -or
            [int]$policyKey.GetValue('TransparentEnabled') -ne [int]$config.SRPConfiguration.TransparentEnabled) {
            throw 'SRP root policy post-apply mismatch'
        }
        foreach ($rule in @($config.PathRules | Where-Object { $_.Enabled })) {
            $rulePath = Join-Path $pathRulesRoot ([string]$rule.Id)
            $ruleKey = Get-Item -LiteralPath $rulePath -ErrorAction Stop
            $rawItemData = $ruleKey.GetValue('ItemData', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($ruleKey.GetValueKind('ItemData').ToString() -ne 'ExpandString' -or [string]$rawItemData -cne [string]$rule.Path -or
                $ruleKey.GetValueKind('Description').ToString() -ne 'String' -or [string]$ruleKey.GetValue('Description') -cne [string]$rule.Description -or
                $ruleKey.GetValueKind('SaferFlags').ToString() -ne 'DWord' -or [int]$ruleKey.GetValue('SaferFlags') -ne [int]$rule.SaferFlags) {
                throw "SRP rule post-apply mismatch: $($rule.Id)"
            }
        }
        Write-Log -Level SUCCESS -Message "SRP configuration completed: $rulesCreated rules created" -Module "AdvancedSecurity"
        Write-Log -Level WARNING -Message "Legacy SRP path rules are configured; runtime enforcement is not proven and Microsoft recommends WDAC or AppLocker on modern Windows" -Module "AdvancedSecurity"

        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  SRP RULES CONFIGURED (CVE-2025-9491)" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Legacy defense-in-depth: Temp/Downloads .lnk path rules configured" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Rules Created:    $rulesCreated" -ForegroundColor Cyan
        Write-Host "Protected Paths:" -ForegroundColor White
        Write-Host "  - Outlook Temp (%LOCALAPPDATA%\Temp\*.lnk)" -ForegroundColor Gray
        Write-Host "  - Downloads    (%USERPROFILE%\Downloads\*.lnk)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Status:           REGISTRY CONFIGURED (runtime enforcement not proven)" -ForegroundColor Yellow
        Write-Host "Microsoft status: SRP deprecated; WDAC/AppLocker preferred" -ForegroundColor Yellow
        Write-Host ""

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure SRP rules: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
