function Test-SRPCompliance {
    [CmdletBinding()]
    param()

    try {
        $configPath = Join-Path $PSScriptRoot '..\Config\SRP-Rules.json'
        $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $policyRoot = [string]$config.RegistryPaths.PolicyRoot
        $policyKey = Get-Item -LiteralPath $policyRoot -ErrorAction Stop
        $errors = [System.Collections.Generic.List[string]]::new()

        if ($policyKey.GetValueNames() -notcontains 'DefaultLevel' -or
            $policyKey.GetValueKind('DefaultLevel').ToString() -ne 'DWord' -or
            [int]$policyKey.GetValue('DefaultLevel') -ne [int]$config.SRPConfiguration.DefaultLevel) {
            $errors.Add('DefaultLevel type/value mismatch')
        }
        if ($policyKey.GetValueNames() -notcontains 'TransparentEnabled' -or
            $policyKey.GetValueKind('TransparentEnabled').ToString() -ne 'DWord' -or
            [int]$policyKey.GetValue('TransparentEnabled') -ne [int]$config.SRPConfiguration.TransparentEnabled) {
            $errors.Add('TransparentEnabled type/value mismatch')
        }

        $pathRulesRoot = [string]$config.RegistryPaths.PathRules
        foreach ($rule in @($config.PathRules | Where-Object { $_.Enabled })) {
            $rulePath = Join-Path $pathRulesRoot ([string]$rule.Id)
            try {
                $ruleKey = Get-Item -LiteralPath $rulePath -ErrorAction Stop
                $rawItemData = $ruleKey.GetValue('ItemData', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($ruleKey.GetValueNames() -notcontains 'ItemData' -or $ruleKey.GetValueKind('ItemData').ToString() -ne 'ExpandString' -or
                    [string]$rawItemData -cne [string]$rule.Path) { $errors.Add("ItemData mismatch: $($rule.Id)") }
                if ($ruleKey.GetValueNames() -notcontains 'Description' -or $ruleKey.GetValueKind('Description').ToString() -ne 'String' -or
                    [string]$ruleKey.GetValue('Description') -cne [string]$rule.Description) { $errors.Add("Description mismatch: $($rule.Id)") }
                if ($ruleKey.GetValueNames() -notcontains 'SaferFlags' -or $ruleKey.GetValueKind('SaferFlags').ToString() -ne 'DWord' -or
                    [int]$ruleKey.GetValue('SaferFlags') -ne [int]$rule.SaferFlags) { $errors.Add("SaferFlags mismatch: $($rule.Id)") }
            }
            catch { $errors.Add("Rule read failed $($rule.Id): $($_.Exception.Message)") }
        }

        # Read-only enforcement-suppression check (owner-informational, never a write).
        # Stock Windows 11 22H2+ install images ship
        # HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp with a non-zero RuleCount.
        # Windows treats a non-zero RuleCount as "AppLocker is configured" and the
        # SAFER/SRP engine then defers to AppLocker and stops enforcing SRP rules
        # (Microsoft's documented SRP-vs-AppLocker precedence; Kanthak 2023 disclosure).
        # If AppLocker is not actually enforcing, the path rules above are registered
        # but inert. We only READ this OS Control key and surface the risk; correcting
        # RuleCount to 0 is an owner decision (out of this module's exact-BAVR scope),
        # not something NoID Privacy writes silently.
        $enforcementWarning = $null
        try {
            $srpGpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp'
            if (Test-Path -LiteralPath $srpGpPath) {
                $gpKey = Get-Item -LiteralPath $srpGpPath -ErrorAction Stop
                if ($gpKey.GetValueNames() -contains 'RuleCount' -and
                    [int]$gpKey.GetValue('RuleCount') -gt 0) {
                    $ruleCount = [int]$gpKey.GetValue('RuleCount')
                    $enforcementWarning = "SRP runtime enforcement is likely SUPPRESSED by the OS: " +
                        "HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp\RuleCount=$ruleCount. " +
                        "Windows treats a non-zero count as 'AppLocker configured' and stops applying SAFER/SRP rules, " +
                        "so the .lnk path rules above may be registered but not enforced. " +
                        "Remediation is owner-gated and NOT applied by NoID Privacy: set that RuleCount to 0 and reboot, " +
                        "or migrate to AppLocker/WDAC (Microsoft's recommended modern controls)."
                }
            }
        }
        catch {
            $enforcementWarning = "Could not read HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp to assess SRP enforcement suppression: $($_.Exception.Message)"
        }

        $compliant = $errors.Count -eq 0
        $details = if ($compliant) { 'Exact stable rule registry state verified; runtime enforcement not asserted' } else { $errors -join '; ' }
        if ($enforcementWarning) { $details = "$details | WARNING: $enforcementWarning" }
        return [PSCustomObject]@{
            Feature='Legacy SRP .lnk path rules'; Status=$(if ($compliant) { 'Registry Configured' } else { 'Mismatch' })
            Compliant=$compliant; Details=$details; EnforcementWarning=$enforcementWarning
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature='Legacy SRP .lnk path rules'; Status='Error'; Compliant=$false
            Details="Test failed: $($_.Exception.Message)"; EnforcementWarning=$null
        }
    }
}
