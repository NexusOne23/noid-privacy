#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/Privacy/Privacy.psm1') -Force
    InModuleScope Privacy {
        # Exercise the real inventory validators and public recovery functions.
        # Session transport and Windows deployment are isolated for this logic
        # regression; these fixtures are not native package-install evidence.
        function script:Get-SessionRestoreReceipt { param($SessionPath) $null = $SessionPath }
        function script:Get-SessionManifest { param($SessionPath) $null = $SessionPath }
        function script:Assert-SessionManifest { param($SessionPath,$Manifest,$RequestedModules) $null = $SessionPath,$Manifest,$RequestedModules }
        function script:Resolve-SessionChildPath { param($SessionPath,$RelativePath) $null = $SessionPath,$RelativePath }
        function script:Write-Log { param($Level,$Message,$Module) $null = $Level,$Message,$Module }

        function script:New-AppRecoveryIdentityFixture {
            param([string]$Contract = 'CurrentV34')
            $config = switch ($Contract) {
                'PreCopilotV32' { Get-PrivacyBloatwareConfig -PreCopilot }
                'PreviousV33' { Get-PrivacyBloatwareConfig -PreviousV33 }
                default { Get-PrivacyBloatwareConfig }
            }
            $schema = if ($Contract -ceq 'PreCopilotV32') { 2 } else { 3 }
            $names = if ($schema -eq 2) { $config.AllRemoveApps } else { $config.RemoveApps }
            $entries = @($names | ForEach-Object {
                $present = $_ -ceq 'Microsoft.XboxApp'
                $mapping = $config.Mappings.$_
                [pscustomobject]@{
                    AppName = [string]$_; Present = $present
                    PackageFullName = if ($present) { 'Microsoft.XboxApp_1.0.0.0_neutral__8wekyb3d8bbwe' } else { $null }
                    PackageFamilyName = if ($present) { 'Microsoft.XboxApp_8wekyb3d8bbwe' } else { $null }
                    Version = if ($present) { '1.0.0.0' } else { $null }
                    ProvisionedPackageNames = @()
                    StoreId = [string]$mapping.StoreId
                    ExpectedPackageNames = @($mapping.ExpectedPackageNames)
                }
            })
            $inventory = [pscustomobject]@{
                SchemaVersion = $schema; Mode = 'standard'; WeatherWidgetRemovalSelected = $false
                InteractiveUserSid = 'S-1-5-21-100-200-300-1001'
                Timestamp = [DateTime]::UtcNow.ToString('o')
                CatalogSha256 = [string]$config.CatalogSha256
                InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entries
                Entries = $entries
            }
            $null = Assert-PrivacyBloatwareActionLog -ActionLog $inventory
            $inventory | ConvertTo-Json -Depth 10 | Set-Content $script:RecoveryInventoryPath -Encoding UTF8
            $script:RecoveryInventoryHash = (Get-FileHash $script:RecoveryInventoryPath).Hash
        }
    }
}

AfterAll {
    Remove-Module Privacy -Force
}

Describe 'Privacy separates original app recovery from a Store replacement' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $session = Join-Path $TestDrive ('Session_AppRecovery_' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -Path (Join-Path $session 'Privacy') -ItemType Directory -Force
        InModuleScope Privacy -Parameters @{ Session = $session } {
            param($Session)
            $script:RecoverySession = $Session
            $script:RecoveryInventoryPath = Join-Path $Session 'Privacy/Privacy_BloatwareActions.json'
            $script:RegisteredApps = @{}
            $script:LocalOutcome = 'Original'
            $script:StoreAvailable = $true
            $script:StoreClientExitCode = 0
            $script:StoreOutcome = 'Success'
            $script:UpdateWorks = $true
            $script:NetworkAvailable = $true
            $script:RecoveryEvents = [Collections.Generic.List[string]]::new()
            Mock Test-NoIDNetworkConnection { $script:NetworkAvailable }
            Mock Get-PrivacyCurrentProcessUserSid { 'S-1-5-21-100-200-300-1001' }
            Mock Get-SessionManifest {
                [pscustomobject]@{ modules = @([pscustomobject]@{
                    name='Privacy'; artifacts=@([pscustomobject]@{
                        type='Privacy';name='Privacy_BloatwareActions';relativePath='Privacy/Privacy_BloatwareActions.json'
                    })
                }) }
            }
            Mock Assert-SessionManifest { }
            Mock Resolve-SessionChildPath { $script:RecoveryInventoryPath }
            Mock Get-AppxPackage { if ($script:RegisteredApps.ContainsKey($Name)) { $script:RegisteredApps[$Name] } }
            Mock Add-AppxPackage {
                if ($script:LocalOutcome -ceq 'Unavailable') { throw 'Original package is not staged' }
                $family = if ($script:LocalOutcome -ceq 'WrongFamily') { 'Microsoft.XboxApp_otherpublisher' } else { $MainPackage }
                $script:RegisteredApps['Microsoft.XboxApp'] = [pscustomobject]@{ Name='Microsoft.XboxApp';PackageFamilyName=$family }
            }
            Mock Get-Command {
                if (-not $script:StoreAvailable) { throw 'Store transport unavailable' }
                [pscustomobject]@{ Path=$env:ComSpec;Source=$env:ComSpec }
            } -ParameterFilter { $Name -eq 'winget' }
            Mock Invoke-PrivacyBoundedProcess {
                $script:RecoveryEvents.Add([string]$ArgumentList[0])
                if ($ArgumentList[0] -ceq 'show') { return $script:StoreClientExitCode }
                if ($ArgumentList[0] -ceq 'install') {
                    if ($script:StoreOutcome -ne 'Success') { return -2147012867 }
                    $script:RegisteredApps['Microsoft.GamingApp'] = [pscustomobject]@{ Name='Microsoft.GamingApp';PackageFamilyName='Microsoft.GamingApp_8wekyb3d8bbwe' }
                }
                0
            }
            Mock Update-PrivacyWinGet {
                $script:RecoveryEvents.Add('update')
                if (-not $script:UpdateWorks) { throw 'App Installer update unavailable' }
                [pscustomobject]@{Path=$env:ComSpec;PreviousVersion='1.21.10120.0';Version='1.29.290.0'}
            }
        }
    }

    It '<Contract>: recognizes the original recorded app already registered' -ForEach @(
        @{Contract='CurrentV34'}, @{Contract='PreviousV33'}, @{Contract='PreCopilotV32'}
    ) {
        InModuleScope Privacy -Parameters @{ Contract=$Contract } {
            param($Contract)
            New-AppRecoveryIdentityFixture -Contract $Contract
            $script:RegisteredApps['Microsoft.XboxApp'] = [pscustomobject]@{ Name='Microsoft.XboxApp';PackageFamilyName='Microsoft.XboxApp_8wekyb3d8bbwe' }
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $assessment.AlreadyPresent | Should -Be 1
            $assessment.Missing | Should -Be 0
        }
    }

    It '<Contract>: verifies local recovery using the original family without a Store install' -ForEach @(
        @{Contract='CurrentV34'}, @{Contract='PreviousV33'}, @{Contract='PreCopilotV32'}
    ) {
        InModuleScope Privacy -Parameters @{ Contract=$Contract } {
            param($Contract)
            New-AppRecoveryIdentityFixture -Contract $Contract
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.RegisteredLocally | Should -Be 1
            $result.InstalledFromStore | Should -Be 0
            $result.Attempted | Should -Be 1
            Should -Invoke Add-AppxPackage -Times 1 -Exactly -ParameterFilter {
                $RegisterByFamilyName -and $MainPackage -ceq 'Microsoft.XboxApp_8wekyb3d8bbwe'
            }
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly
            (Get-FileHash $script:RecoveryInventoryPath).Hash | Should -BeExactly $script:RecoveryInventoryHash
        }
    }

    It 'continues to recognize the currently supported Store replacement' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:RegisteredApps['Microsoft.GamingApp'] = [pscustomobject]@{ Name='Microsoft.GamingApp';PackageFamilyName='Microsoft.GamingApp_8wekyb3d8bbwe' }
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $assessment.AlreadyPresent | Should -Be 1
            $assessment.Missing | Should -Be 0
        }
    }

    It 'does not certify another family as the locally restored original' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome = 'WrongFamily'; $script:StoreAvailable = $false
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.RegisteredLocally | Should -Be 0
            $result.Failed | Should -Be 1
        }
    }

    It 'uses and verifies the Store replacement when local registration fails' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome = 'Unavailable'
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.RegisteredLocally | Should -Be 0
            $result.InstalledFromStore | Should -Be 1
            $result.Attempted | Should -Be 1
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 1 -Exactly -ParameterFilter {
                $ArgumentList[0] -ceq 'install' -and $ArgumentList[2] -ceq '9MV0B5HZVK9Z'
            }
            Should -Invoke Update-PrivacyWinGet -Times 0 -Exactly
        }
    }

    It 'updates an incompatible WinGet client before Store installation: <Code>' -ForEach @(
        @{Code=-1978335230}, @{Code=-1978335176}, @{Code=-1978335170}, @{Code=-1978335138}
    ) {
        InModuleScope Privacy -Parameters @{ Code=$Code } {
            param($Code)
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome='Unavailable'; $script:StoreClientExitCode=$Code
            $result=Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.InstalledFromStore | Should -Be 1
            @($script:RecoveryEvents | Where-Object { $_ -in @('show','update','install') }) | Should -Be @('show','update','install')
            Should -Invoke Update-PrivacyWinGet -Times 1 -Exactly
            (Get-FileHash $script:RecoveryInventoryPath).Hash | Should -BeExactly $script:RecoveryInventoryHash
        }
    }

    It 'does not update WinGet for an ordinary network failure' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome='Unavailable'; $script:StoreClientExitCode=-2147012867
            $script:StoreOutcome='Failure'
            $result=Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.Failed | Should -Be 1
            Should -Invoke Update-PrivacyWinGet -Times 0 -Exactly
        }
    }

    It 'retains a failed recovery verdict when the required WinGet update fails' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome='Unavailable'; $script:StoreClientExitCode=-1978335138; $script:UpdateWorks=$false
            $result=Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.Failed | Should -Be 1
            $result.Attempted | Should -Be 1
            $result.InstalledFromStore | Should -Be 0
            Should -Invoke Update-PrivacyWinGet -Times 1 -Exactly
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly -ParameterFilter { $ArgumentList[0] -ceq 'install' }
        }
    }

    It 'defers the Store route without a network connection and reports it as information' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:LocalOutcome = 'Unavailable'; $script:NetworkAvailable = $false
            $script:LoggedLevels = [Collections.Generic.List[string]]::new()
            Mock Write-Log { $script:LoggedLevels.Add([string]$Level) }
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.Status | Should -Be 'NeedsNetwork'
            $result.NeedsNetwork | Should -Be 1
            $result.Failed | Should -Be 0
            $result.Attempted | Should -Be 0
            ($result.Details -join ' ') | Should -Match 'needs the Microsoft Store and a network connection'
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly
            Should -Invoke Update-PrivacyWinGet -Times 0 -Exactly
            $script:LoggedLevels | Should -Not -Contain 'WARNING'
            $script:LoggedLevels | Should -Not -Contain 'ERROR'
        }
    }

    It 'performs no WinGet update or deployment when app recovery is cancelled' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:StoreClientExitCode=-1978335138
            $result=Restore-BloatwareApps -SessionPath $script:RecoverySession -WhatIf
            $result.Status | Should -Be 'Cancelled'
            Should -Invoke Update-PrivacyWinGet -Times 0 -Exactly
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly
            Should -Invoke Add-AppxPackage -Times 0 -Exactly
        }
    }
}
