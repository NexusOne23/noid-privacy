#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repoRoot 'Tools/Verify-Complete-Hardening.ps1'),
        [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Verifier syntax is invalid' }
    $loops = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
                $node.Condition.Extent.Text -ceq '$edgeTargets'
            }, $true))
    if ($loops.Count -ne 1) { throw 'Expected the single production Edge verification loop' }
    $script:VerifyEdgeTargets = [scriptblock]::Create($loops[0].Extent.Text)

    function Test-NoIDRegistryKey {
        param([string]$LiteralPath)
        if ($LiteralPath -cne 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist') {
            throw 'Unexpected registry target'
        }
        return $true
    }

    function Invoke-TestEdgeVerification {
        param([bool]$DecisionKnown = $true, [bool]$AllowExtensions = $true)
        $results = @{ Verified = 0; Failed = 0; NotChecked = 0; NotApplicable = 0 }
        $edgePassed = @(); $edgeFailed = @(); $edgeNotChecked = @(); $edgeNotApplicable = @()
        $edgeExtensionDecisionKnown = $DecisionKnown
        $edgeAllowExtensionsSelected = $AllowExtensions
        $edgeTargets = @([pscustomobject]@{
                Name = '1'; Path = 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
                Type = 'String'; Value = '*'; Applicable = $true
            })
        # Execute the production loop; the fixture only supplies input and collects output.
        . $script:VerifyEdgeTargets
        return [pscustomobject]@{
            Counts = $results; Passed = $edgePassed; Failed = $edgeFailed
            NotChecked = $edgeNotChecked; NotApplicable = $edgeNotApplicable
            DecisionKnown = $edgeExtensionDecisionKnown; AllowExtensions = $edgeAllowExtensionsSelected
            Targets = $edgeTargets.Count
        }
    }
}

Describe 'Edge verification follows the selected blocklist scope' {
    BeforeEach {
        $script:edgeVerifierKey = [pscustomobject]@{ Exists = $true; Kind = 'String'; Data = '*' }
        $script:edgeVerifierKey | Add-Member ScriptMethod GetValueNames {
            if ($this.Exists) { return @('1') }; return @()
        }
        $script:edgeVerifierKey | Add-Member ScriptMethod GetValueKind {
            param($name)
            if ($name -cne '1') { throw 'Unexpected registry value name' }
            return $this.Kind
        }
        $script:edgeVerifierKey | Add-Member ScriptMethod GetValue {
            param($name, $fallback, $options)
            if ($name -cne '1' -or $null -ne $fallback -or
                $options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) {
                throw 'Unexpected registry read contract'
            }
            return $this.Data
        }
        Mock Get-Item { return $script:edgeVerifierKey }
    }

    It 'keeps an unmanaged <Kind>/<Data> entry by choice without counting it as verified' -TestCases @(
        @{ Kind = 'String'; Data = '*' }
        @{ Kind = 'String'; Data = 'administrator-selected-extension' }
        @{ Kind = 'DWord'; Data = 1 }
    ) {
        param($Kind, $Data)
        $script:edgeVerifierKey.Kind = $Kind; $script:edgeVerifierKey.Data = $Data
        $observed = Invoke-TestEdgeVerification
        $observed.Counts.Verified | Should -Be 0
        $observed.Counts.Failed | Should -Be 0
        $observed.Counts.NotChecked | Should -Be 1
        $observed.NotChecked[0].VerificationDisposition | Should -BeExactly 'ByChoice'
        $observed.NotChecked[0].VerificationEvidenceSource | Should -BeExactly 'ApplyIntent'
        $observed.NotChecked[0].Actual | Should -Match ([regex]::Escape("$Kind/$Data"))
        $observed.NotChecked[0].Actual | Should -Match 'Existing blocks remain'
        $script:edgeVerifierKey.Data | Should -Be $Data
    }

    It 'reports an absent unmanaged entry by choice without claiming an applied block' {
        $script:edgeVerifierKey.Exists = $false
        $observed = Invoke-TestEdgeVerification
        $observed.Counts.Verified | Should -Be 0
        $observed.Counts.Failed | Should -Be 0
        $observed.Counts.NotChecked | Should -Be 1
        $observed.NotChecked[0].VerificationDisposition | Should -BeExactly 'ByChoice'
        $observed.NotChecked[0].Actual | Should -Match 'entry absent'
    }

    It 'verifies an explicitly selected exact block' {
        $observed = Invoke-TestEdgeVerification -AllowExtensions $false
        $observed.Counts.Verified | Should -Be 1
        $observed.Counts.Failed | Should -Be 0
        $observed.Counts.NotChecked | Should -Be 0
    }

    It 'fails a selected block that is <Case>' -TestCases @(
        @{ Case = 'missing'; Exists = $false; Kind = 'String'; Data = '*' }
        @{ Case = 'the wrong type'; Exists = $true; Kind = 'ExpandString'; Data = '*' }
        @{ Case = 'the wrong value'; Exists = $true; Kind = 'String'; Data = 'specific-extension' }
    ) {
        param($Case, $Exists, $Kind, $Data)
        $script:edgeVerifierKey.Exists = $Exists
        $script:edgeVerifierKey.Kind = $Kind; $script:edgeVerifierKey.Data = $Data
        $observed = Invoke-TestEdgeVerification -AllowExtensions $false
        $observed.Counts.Verified | Should -Be 0
        $observed.Counts.Failed | Should -Be 1 -Because "the selected block is $Case"
        $observed.Counts.NotChecked | Should -Be 0
    }

    It 'does not infer a choice from an existing block' {
        $observed = Invoke-TestEdgeVerification -DecisionKnown $false
        $observed.Counts.Verified | Should -Be 0
        $observed.Counts.Failed | Should -Be 0
        $observed.Counts.NotChecked | Should -Be 1
        $observed.NotChecked[0].VerificationDisposition | Should -BeExactly 'NoSavedChoice'
    }

    It 'propagates a registry read failure instead of treating it as an excluded choice' {
        Mock Get-Item { throw 'Registry read unavailable' }
        { Invoke-TestEdgeVerification } | Should -Throw '*Registry read unavailable*'
    }
}
