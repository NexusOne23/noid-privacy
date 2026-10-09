#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $script:RepoRoot 'Tests/Windows11/Invoke-Windows11DecisionMatrix.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Windows state runner has syntax errors' }
    foreach ($name in @('Get-RegistryTreeState', 'ConvertTo-CanonicalValue')) {
        $definition = @($ast.FindAll({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $true))
        if ($definition.Count -ne 1) { throw 'Registry fingerprint helper is ambiguous' }
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }
    $roots = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$registryRoots'
    }, $true)
    $script:TreeRoots = @($roots.Right.FindAll({ param($node)
        $node -is [Management.Automation.Language.StringConstantExpressionAst]
    }, $true) | ForEach-Object Value)
    $assignment = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$additionalRegistryValues'
    }, $true)
    $table = $assignment.Right.Find({ param($node)
        $node -is [Management.Automation.Language.HashtableAst]
    }, $true)
    $script:ValueRoots = @{}
    foreach ($pair in $table.KeyValuePairs) {
        $script:ValueRoots[[string]$pair.Item1.Value] = @($pair.Item2.FindAll({ param($node)
            $node -is [Management.Automation.Language.StringConstantExpressionAst]
        }, $true) | ForEach-Object Value)
    }

    function Test-FingerprintTargetCoverage {
        param([string]$Path, [string]$Name, [hashtable]$Values)
        foreach ($root in $script:TreeRoots) {
            if ($Path.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
                $Path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $Values.ContainsKey($Path) -and $Name -in $Values[$Path]
    }
}

Describe 'Independent Windows registry fingerprint coverage' {
    It 'rejects a user-hive measurement without an explicit desktop identity' {
        { Get-RegistryTreeState -Roots 'HKCU:\Software\Policies' } |
            Should -Throw '*requires a resolved interactive user SID*'
    }

    It 'rejects malformed identities before opening a registry hive' {
        foreach ($identity in @('S-1-5-18', 'S-1-5-21-1-2-3-1001\Software', 'S-1-5-21--', '..')) {
            { Get-RegistryTreeState -Roots 'HKCU:\Software\Policies' -InteractiveUserSid $identity } |
                Should -Throw '*requires a resolved interactive user SID*'
        }
    }

    It 'does not report a missing user hive as an empty recovered configuration' {
        { Get-RegistryTreeState -Roots 'HKCU:\Software\Policies' -InteractiveUserSid 'S-1-5-21-0-0-0-4294967295' } |
            Should -Throw '*Interactive user registry hive is not loaded*'
    }

    It 'covers every declared baseline registry policy and security-template value' {
        $targets = [Collections.Generic.List[object]]::new()
        foreach ($scope in @('Computer', 'User')) {
            $path = Join-Path $script:RepoRoot "Modules/SecurityBaseline/ParsedSettings/$scope-RegistryPolicies.json"
            $hive = if ($scope -eq 'Computer') { 'HKLM:\' } else { 'HKCU:\' }
            foreach ($policy in (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)) {
                $name = [string]$policy.ValueName -replace '^\*\*del\.', ''
                $targets.Add(@{ Path=$hive + ([string]$policy.KeyName).Trim('[', ']'); Name=$name })
            }
        }
        $templatePath = Join-Path $script:RepoRoot 'Modules/SecurityBaseline/ParsedSettings/SecurityTemplates.json'
        $template = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
        foreach ($group in $template.PSObject.Properties) {
            $section = $group.Value.PSObject.Properties['Registry Values']
            if ($null -eq $section) { continue }
            foreach ($entry in $section.Value.PSObject.Properties) {
                $path = ([string]$entry.Name) -replace '^MACHINE\\', 'HKLM:\'
                $separator = $path.LastIndexOf('\')
                $targets.Add(@{ Path=$path.Substring(0, $separator); Name=$path.Substring($separator + 1) })
            }
        }
        $targets.Count | Should -BeGreaterThan 335
        $missing = @($targets | Where-Object {
            -not (Test-FingerprintTargetCoverage -Path $_.Path -Name $_.Name -Values $script:ValueRoots)
        })
        $missing.Count | Should -Be 0 -Because (($missing | ForEach-Object { $_.Path + '\' + $_.Name }) -join ', ')
    }

    It 'detects a missing covered value without capturing adjacent Winlogon credentials' {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Test-FingerprintTargetCoverage -Path $path -Name ScRemoveOption -Values $script:ValueRoots | Should -BeTrue
        Test-FingerprintTargetCoverage -Path $path -Name DefaultPassword -Values $script:ValueRoots | Should -BeFalse
        $incomplete = $script:ValueRoots.Clone()
        $incomplete.Remove($path)
        Test-FingerprintTargetCoverage -Path $path -Name ScRemoveOption -Values $incomplete | Should -BeFalse
    }

    It 'captures both Copilot URI handlers in both real source hives' {
        foreach ($hive in @('HKLM:', 'HKCU:')) {
            foreach ($handler in @('ms-copilot', 'ms-edge-copilot')) {
                $script:TreeRoots | Should -Contain "$hive\SOFTWARE\Classes\$handler"
            }
        }
    }

    It 'covers every additional local control the native Device Guard backend can materialize' {
        . (Join-Path $script:RepoRoot 'Modules/SecurityBaseline/Private/Get-SecurityBaselineDeviceGuardPlan.ps1')
        $targets = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)
        $targets.Count | Should -Be 20
        foreach ($target in $targets) {
            $path = 'HKLM:\' + $target.KeyName.Substring(1)
            Test-FingerprintTargetCoverage -Path $path -Name $target.ValueName -Values $script:ValueRoots |
                Should -BeTrue -Because ($path + '\' + $target.ValueName + ' is part of recorded native-processing recovery')
        }
    }

    It 'detects missing kernel-stack metadata coverage without widening capture to adjacent Device Guard secrets' {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks'
        $incomplete = $script:ValueRoots.Clone()
        $incomplete[$path] = @($incomplete[$path] | Where-Object { $_ -notin @('AuditModeEnabled', 'WasEnabledBy') })
        foreach ($name in @('AuditModeEnabled', 'WasEnabledBy')) {
            Test-FingerprintTargetCoverage -Path $path -Name $name -Values $script:ValueRoots | Should -BeTrue
            Test-FingerprintTargetCoverage -Path $path -Name $name -Values $incomplete | Should -BeFalse
        }
        Test-FingerprintTargetCoverage -Path $path -Name Locked -Values $incomplete | Should -BeTrue
        Test-FingerprintTargetCoverage -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
            -Name IsolatedCredentialsRootSecret -Values $script:ValueRoots | Should -BeFalse
    }
}
