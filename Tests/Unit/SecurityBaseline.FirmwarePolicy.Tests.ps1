#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ProfilePath = Join-Path $script:RepoRoot 'Modules/SecurityBaseline/ParsedSettings/Computer-RegistryPolicies.json'
    . (Join-Path $script:RepoRoot 'Modules/SecurityBaseline/Private/Get-RecoverableSecurityBaselinePolicies.ps1')
    $script:LockTargets = @(
        @{ Key = '[Software\Policies\Microsoft\Windows\System'; Name = 'RunAsPPL' }
        @{ Key = '[SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL' }
        @{ Key = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags' }
        @{ Key = '[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'HypervisorEnforcedCodeIntegrity' }
    )
}

Describe 'SecurityBaseline firmware protection plan' {
    BeforeEach {
        $script:Policies = Get-Content -LiteralPath $script:ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    It 'keeps all four protections enabled without requesting UEFI locks' {
        $plan = @(Get-RecoverableSecurityBaselinePolicies -Policies $script:Policies)
        foreach ($target in $script:LockTargets) {
            $matchesForTarget = @($plan | Where-Object {
                    $_.KeyName -ieq $target.Key -and $_.ValueName -ieq $target.Name
                })
            $matchesForTarget.Count | Should -Be 1
            $matchesForTarget[0].Type | Should -BeExactly 'REG_DWORD'
            $matchesForTarget[0].Data | Should -Be 2
        }
    }

    It 'retains source bytes and all security directives while excluding native format metadata' {
        $sourceHash = (Get-FileHash -LiteralPath $script:ProfilePath -Algorithm SHA256).Hash
        $sourceJson = ConvertTo-Json -InputObject $script:Policies -Depth 20 -Compress
        $plan = @(Get-RecoverableSecurityBaselinePolicies -Policies $script:Policies)
        $plan.Count | Should -Be 330
        $sourceTargets = @($script:Policies | Where-Object {
                -not ($_.KeyName -ieq '[Software\Policies\Microsoft\WindowsFirewall' -and $_.ValueName -ieq 'PolicyVersion')
            })
        $changed = 0
        for ($index = 0; $index -lt $plan.Count; $index++) {
            $before = ConvertTo-Json -InputObject $sourceTargets[$index] -Depth 20 -Compress
            $after = ConvertTo-Json -InputObject $plan[$index] -Depth 20 -Compress
            if ($before -cne $after) {
                $changed++
                $expected = $sourceTargets[$index].PSObject.Copy()
                $expected.Data = 2
                $after | Should -BeExactly (ConvertTo-Json -InputObject $expected -Depth 20 -Compress)
            }
        }
        $changed | Should -Be 4
        (ConvertTo-Json -InputObject $script:Policies -Depth 20 -Compress) | Should -BeExactly $sourceJson
        (Get-FileHash -LiteralPath $script:ProfilePath -Algorithm SHA256).Hash | Should -BeExactly $sourceHash
    }

    It 'does not rewrite a same-named value under an unrelated key' {
        $canary = [PSCustomObject]@{ GPO = 'Test'; KeyName = '[SOFTWARE\NoIDFirmwareCanary'; ValueName = 'RunAsPPL'; Type = 'REG_DWORD'; Data = 1 }
        $plan = @(Get-RecoverableSecurityBaselinePolicies -Policies @($script:Policies + $canary))
        $plan[-1].Data | Should -Be 1
    }

    It 'fails without changing input if a directive is <Fault>' -TestCases @(
        @{ Fault = 'missing' }, @{ Fault = 'duplicated' }, @{ Fault = 'wrong-type' },
        @{ Fault = 'unexpected-data' }, @{ Fault = 'boolean-data' }, @{ Fault = 'wrong-key' }
    ) {
        param($Fault)
        foreach ($target in $script:LockTargets) {
            $candidate = Get-Content -LiteralPath $script:ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $entry = @($candidate | Where-Object { $_.KeyName -ieq $target.Key -and $_.ValueName -ieq $target.Name })[0]
            switch ($Fault) {
                'missing' { $candidate = @($candidate | Where-Object { $_ -ne $entry }) }
                'duplicated' { $candidate += $entry.PSObject.Copy() }
                'wrong-type' { $entry.Type = 'REG_SZ' }
                'unexpected-data' { $entry.Data = 0 }
                'boolean-data' { $entry.Data = $true }
                'wrong-key' { $entry.KeyName += '\Foreign' }
            }
            $before = ConvertTo-Json -InputObject $candidate -Depth 20 -Compress
            { Get-RecoverableSecurityBaselinePolicies -Policies $candidate } | Should -Throw '*firmware protection source directive*'
            (ConvertTo-Json -InputObject $candidate -Depth 20 -Compress) | Should -BeExactly $before
        }
    }

    It 'works with strict-mode source records' {
        Set-StrictMode -Version Latest
        @(Get-RecoverableSecurityBaselinePolicies -Policies $script:Policies).Count | Should -Be 330
    }

    It 'preserves an unrelated same-named policy-format value' {
        $canary = [pscustomobject]@{ GPO='Test';KeyName='[SOFTWARE\NoIDPolicyCanary';ValueName='PolicyVersion';Type='REG_DWORD';Data=538 }
        $plan = @(Get-RecoverableSecurityBaselinePolicies -Policies @($script:Policies + $canary))
        $plan.Count | Should -Be 331
        ($plan[-1] | ConvertTo-Json -Compress) | Should -BeExactly ($canary | ConvertTo-Json -Compress)
    }

    It 'rejects an unreviewed policy-format source entry: <Fault>' -TestCases @(
        @{Fault='missing'}, @{Fault='duplicate'}, @{Fault='wrong type'},
        @{Fault='changed version'}, @{Fault='string value'}
    ) {
        param($Fault)
        $entry = @($script:Policies | Where-Object {
                $_.KeyName -ieq '[Software\Policies\Microsoft\WindowsFirewall' -and $_.ValueName -ieq 'PolicyVersion'
            })[0]
        switch -Exact ($Fault) {
            'missing' { $script:Policies=@($script:Policies | Where-Object { $_ -ne $entry }) }
            'duplicate' { $script:Policies+= $entry.PSObject.Copy() }
            'wrong type' { $entry.Type='REG_SZ' }
            'changed version' { $entry.Data=545 }
            'string value' { $entry.Data='538' }
        }
        $before = ConvertTo-Json -InputObject $script:Policies -Depth 20 -Compress
        { Get-RecoverableSecurityBaselinePolicies -Policies $script:Policies } | Should -Throw '*policy-format source entry*'
        (ConvertTo-Json -InputObject $script:Policies -Depth 20 -Compress) | Should -BeExactly $before
    }
}
