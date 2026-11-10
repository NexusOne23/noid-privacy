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

        # The retired Xbox Console Companion is recorded only by catalog v3.5
        # and earlier; its Store replacement stays usable through the current
        # map's recovery-only route.
        function script:New-AppRecoveryIdentityFixture {
            param([string]$Contract = 'PreviousV35')
            $config = switch ($Contract) {
                'PreCopilotV32' { Get-PrivacyBloatwareConfig -PreCopilot }
                'PreviousV33' { Get-PrivacyBloatwareConfig -PreviousV33 }
                'PreviousV34' { Get-PrivacyBloatwareConfig -PreviousV34 }
                'PreviousV35' { Get-PrivacyBloatwareConfig -PreviousV35 }
                default { throw "Unknown catalog contract: $Contract" }
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
        @{Contract='PreviousV35'}, @{Contract='PreviousV34'}, @{Contract='PreviousV33'}, @{Contract='PreCopilotV32'}
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
        @{Contract='PreviousV35'}, @{Contract='PreviousV34'}, @{Contract='PreviousV33'}, @{Contract='PreCopilotV32'}
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

Describe 'Privacy recovers apps for the signed-in user when the elevated process runs as another account' -Skip:($env:OS -ne 'Windows_NT') {
    # Windows Administrator protection elevates through a separate account
    # (ADMIN_<user>); a standard user can also elevate with another
    # administrator's credentials. The sealed inventory belongs to ...-1001.
    BeforeEach {
        $session = Join-Path $TestDrive ('Session_AppRecoveryAP_' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -Path (Join-Path $session 'Privacy') -ItemType Directory -Force
        InModuleScope Privacy -Parameters @{ Session = $session } {
            param($Session)
            $script:RecoverySession = $Session
            $script:RecoveryInventoryPath = Join-Path $Session 'Privacy/Privacy_BloatwareActions.json'
            $script:DesktopSid = 'S-1-5-21-100-200-300-1001'
            $script:AppxUserQueries = [Collections.Generic.List[string]]::new()
            Mock Get-PrivacyCurrentProcessUserSid { 'S-1-5-21-100-200-300-1002' }
            Mock Test-PrivacyProcessElevated { $true }
            Mock Get-PrivacyUserContext {
                [pscustomobject]@{ Account = 'PC\User'; Sid = $script:DesktopSid; SessionId = 1; Root = "HKU:\$script:DesktopSid" }
            }
            Mock Get-SessionManifest {
                [pscustomobject]@{ modules = @([pscustomobject]@{
                    name='Privacy'; artifacts=@([pscustomobject]@{
                        type='Privacy';name='Privacy_BloatwareActions';relativePath='Privacy/Privacy_BloatwareActions.json'
                    })
                }) }
            }
            Mock Assert-SessionManifest { }
            Mock Resolve-SessionChildPath { $script:RecoveryInventoryPath }
            Mock Get-AppxPackage { $script:AppxUserQueries.Add([string]$User) }
            Mock Invoke-PrivacyAppRecoveryLoop { throw 'in-process recovery must not run for another account' }
        }
    }

    It 'checks the signed-in original user''s registrations and selects the desktop-user worker' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $assessment.Status | Should -Be 'Needed'
            $assessment.RecoveryContext | Should -Be 'DesktopUserWorker'
            $assessment.OriginalUserSid | Should -Be 'S-1-5-21-100-200-300-1001'
            $assessment.CurrentUserSid | Should -Be 'S-1-5-21-100-200-300-1002'
            $assessment.Missing | Should -Be 1
            @($script:AppxUserQueries | Sort-Object -Unique) | Should -Be @('S-1-5-21-100-200-300-1001')
        }
    }

    It 'still requires the original user when another account is signed in at this desktop' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            $script:DesktopSid = 'S-1-5-21-100-200-300-1003'
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Success | Should -BeFalse
            $assessment.Status | Should -Be 'OriginalUserRequired'
            $assessment.RecoveryContext | Should -Be ''
            $assessment.Error | Should -Match 'S-1-5-21-100-200-300-1001, who is not signed in at this desktop'
            Should -Invoke Get-AppxPackage -Times 0 -Exactly
        }
    }

    It 'still requires the original user from a process without administrator rights' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            Mock Test-PrivacyProcessElevated { $false }
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Status | Should -Be 'OriginalUserRequired'
            Should -Invoke Get-PrivacyUserContext -Times 0 -Exactly
            Should -Invoke Get-AppxPackage -Times 0 -Exactly
        }
    }

    It 'keeps the in-process route for the original user itself' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            Mock Get-PrivacyCurrentProcessUserSid { 'S-1-5-21-100-200-300-1001' }
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:RecoverySession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $assessment.RecoveryContext | Should -Be 'CurrentProcess'
            @($script:AppxUserQueries | Where-Object { $_ }).Count | Should -Be 0
        }
    }

    It 'recovers through the desktop-user worker and reports its verified outcome' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            Mock Invoke-PrivacyDesktopUserAppRecovery {
                [pscustomobject]@{
                    SchemaVersion=1;UserSid=$User.Sid;SessionId=1;Success=$true
                    Attempted=1;Reinstalled=1;RegisteredLocally=1;InstalledFromStore=0;Failed=0;Skipped=0;NeedsNetwork=0
                    Details=@('Microsoft.XboxApp: re-registered and verified from sealed package family Microsoft.XboxApp_8wekyb3d8bbwe.')
                    Apps=@([pscustomobject]@{AppName='Microsoft.XboxApp';Outcome='RegisteredLocally'});Error=''
                }
            }
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.Status | Should -Be 'Completed'
            $result.RegisteredLocally | Should -Be 1
            $result.Attempted | Should -Be 1
            @($result.AppOutcomes).Count | Should -Be 1
            Should -Invoke Invoke-PrivacyDesktopUserAppRecovery -Times 1 -Exactly -ParameterFilter {
                $User.Sid -ceq 'S-1-5-21-100-200-300-1001' -and @($MissingApps).Count -eq 1 -and $MissingApps[0].AppName -ceq 'Microsoft.XboxApp'
            }
            Should -Invoke Invoke-PrivacyAppRecoveryLoop -Times 0 -Exactly
        }
    }

    It 'reports every app as skipped when the desktop-user worker cannot run' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            Mock Invoke-PrivacyDesktopUserAppRecovery { throw 'Task Scheduler is unavailable' }
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.Status | Should -Be 'Failed'
            $result.Skipped | Should -Be 1
            $result.Attempted | Should -Be 0
            ($result.Details -join ' ') | Should -Match "Microsoft\.XboxApp: app recovery in the signed-in user's account could not run: Task Scheduler is unavailable"
        }
    }

    It 'refuses recovery when the signed-in desktop user changed after the assessment' {
        InModuleScope Privacy {
            New-AppRecoveryIdentityFixture
            Mock Invoke-PrivacyDesktopUserAppRecovery { throw 'must not start' }
            $script:ContextCalls = 0
            Mock Get-PrivacyUserContext {
                $script:ContextCalls++
                $sid = if ($script:ContextCalls -eq 1) { $script:DesktopSid } else { 'S-1-5-21-100-200-300-1003' }
                [pscustomobject]@{ Account = 'PC\User'; Sid = $sid; SessionId = 1; Root = "HKU:\$sid" }
            }
            $result = Restore-BloatwareApps -SessionPath $script:RecoverySession -Confirm:$false
            $result.Success | Should -BeFalse
            ($result.Details -join ' ') | Should -Match 'desktop user changed after the app assessment'
            Should -Invoke Invoke-PrivacyDesktopUserAppRecovery -Times 0 -Exactly
        }
    }
}

Describe 'Privacy desktop-user app recovery boundary' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeAll {
        InModuleScope Privacy {
            function script:New-AppRecoveryRequestFixture {
                [pscustomobject]@{
                    SchemaVersion = 1; UserSid = 'S-1-5-21-100-200-300-1001'; SessionId = 1
                    Apps = @([pscustomobject]@{
                        AppName = 'Microsoft.XboxApp'; StoreId = '9MV0B5HZVK9Z'
                        ExpectedPackageNames = @('Microsoft.GamingApp')
                        VerificationPackageNames = @('Microsoft.GamingApp', 'Microsoft.XboxApp')
                        PackageFamilyNames = @('Microsoft.XboxApp_8wekyb3d8bbwe')
                        CanRegisterLocally = $true; CanUseStore = $true
                    })
                }
            }
            function script:New-AppRecoveryResultFixture {
                param([string]$Outcome = 'RegisteredLocally')
                $local = [int]($Outcome -ceq 'RegisteredLocally'); $store = [int]($Outcome -ceq 'InstalledFromStore')
                $failed = [int]($Outcome -ceq 'Failed')
                [pscustomobject]@{
                    SchemaVersion = 1; UserSid = 'S-1-5-21-100-200-300-1001'; SessionId = 1
                    Success = ($failed -eq 0 -and $Outcome -cnotin @('Skipped','NeedsNetwork'))
                    Attempted = $local + $store + $failed; Reinstalled = $local + $store
                    RegisteredLocally = $local; InstalledFromStore = $store; Failed = $failed
                    Skipped = [int]($Outcome -ceq 'Skipped'); NeedsNetwork = [int]($Outcome -ceq 'NeedsNetwork')
                    Details = @('detail'); Apps = @([pscustomobject]@{ AppName = 'Microsoft.XboxApp'; Outcome = $Outcome }); Error = ''
                }
            }
        }
    }

    It 'accepts a well-formed request bound to the desktop user' {
        InModuleScope Privacy {
            $apps = @(Assert-PrivacyAppRecoveryRequest -Request (New-AppRecoveryRequestFixture) -ExpectedSid 'S-1-5-21-100-200-300-1001' -ExpectedSessionId 1)
            $apps.Count | Should -Be 1
        }
    }

    It 'rejects a request that <Case>' -ForEach @(
        @{ Case = 'names another user'; Change = { param($r) $r.UserSid = 'S-1-5-21-100-200-300-1002' } }
        @{ Case = 'names another session'; Change = { param($r) $r.SessionId = 2 } }
        @{ Case = 'carries an extra field'; Change = { param($r) $r | Add-Member -NotePropertyName Command -NotePropertyValue 'calc' } }
        @{ Case = 'carries a malformed package family'; Change = { param($r) $r.Apps[0].PackageFamilyNames = @('Microsoft.XboxApp_8wekyb3d8bbwe;calc') } }
        @{ Case = 'carries a malformed Store ID'; Change = { param($r) $r.Apps[0].StoreId = '9MV0B5HZVK9Z --source x' } }
        @{ Case = 'claims a Store route without a product'; Change = { param($r) $r.Apps[0].StoreId = '' } }
        @{ Case = 'has no recovery route'; Change = { param($r) $r.Apps[0].PackageFamilyNames = @(); $r.Apps[0].CanRegisterLocally = $false; $r.Apps[0].CanUseStore = $false } }
        @{ Case = 'verifies other package names'; Change = { param($r) $r.Apps[0].VerificationPackageNames = @('Microsoft.GamingApp') } }
        @{ Case = 'repeats an app'; Change = { param($r) $r.Apps = @($r.Apps[0], $r.Apps[0]) } }
    ) {
        InModuleScope Privacy -Parameters @{ Change = $Change } {
            param($Change)
            $request = New-AppRecoveryRequestFixture
            & $Change $request
            { Assert-PrivacyAppRecoveryRequest -Request $request -ExpectedSid 'S-1-5-21-100-200-300-1001' -ExpectedSessionId 1 } |
                Should -Throw '*Privacy app recovery request*'
        }
    }

    It 'accepts a consistent worker result for <Outcome>' -ForEach @(
        @{ Outcome = 'RegisteredLocally' }, @{ Outcome = 'InstalledFromStore' }, @{ Outcome = 'Failed' },
        @{ Outcome = 'Skipped' }, @{ Outcome = 'NeedsNetwork' }
    ) {
        InModuleScope Privacy -Parameters @{ Outcome = $Outcome } {
            param($Outcome)
            $record = New-AppRecoveryResultFixture -Outcome $Outcome
            { Assert-PrivacyAppRecoveryWorkerResult -Record $record `
                -UserSid 'S-1-5-21-100-200-300-1001' -SessionId 1 -AppNames @('Microsoft.XboxApp') } | Should -Not -Throw
        }
    }

    It 'rejects a worker result that <Case>' -ForEach @(
        @{ Case = 'names another user'; Change = { param($r) $r.UserSid = 'S-1-5-21-100-200-300-1002' }; Message = '*schema or user binding*' }
        @{ Case = 'omits a requested app'; Change = { param($r) $r.Apps = @(); $r.Attempted = 0; $r.Reinstalled = 0; $r.RegisteredLocally = 0 }; Message = '*every requested app*' }
        @{ Case = 'adds an app that was not requested'; Change = { param($r) $r.Apps = @($r.Apps[0], [pscustomobject]@{ AppName = 'Microsoft.BingWeather'; Outcome = 'Failed' }) }; Message = '*every requested app*' }
        @{ Case = 'claims success with a failed app'; Change = { param($r) $r.Apps[0].Outcome = 'Failed' }; Message = '*counters do not match*' }
        @{ Case = 'uses an unknown outcome'; Change = { param($r) $r.Apps[0].Outcome = 'Recovered' }; Message = '*invalid app outcome*' }
        @{ Case = 'reports a worker failure'; Change = { param($r) $r.Apps = @(); $r.Success = $false; $r.Attempted = 0; $r.Reinstalled = 0; $r.RegisteredLocally = 0; $r.Error = 'identity mismatch' }; Message = '*worker failed: identity mismatch*' }
    ) {
        InModuleScope Privacy -Parameters @{ Change = $Change; Message = $Message } {
            param($Change, $Message)
            $record = New-AppRecoveryResultFixture
            & $Change $record
            { Assert-PrivacyAppRecoveryWorkerResult -Record $record -UserSid 'S-1-5-21-100-200-300-1001' -SessionId 1 -AppNames @('Microsoft.XboxApp') } |
                Should -Throw $Message
        }
    }

    It 'turns a reported recovery into a failure when the app is not registered for the user' {
        InModuleScope Privacy {
            Mock Get-AppxPackage { }
            $apps = @((New-AppRecoveryRequestFixture).Apps)
            $record = Confirm-PrivacyDesktopUserAppRecovery -Record (New-AppRecoveryResultFixture) -MissingApps $apps -UserSid 'S-1-5-21-100-200-300-1001'
            $record.Success | Should -BeFalse
            $record.Failed | Should -Be 1
            $record.RegisteredLocally | Should -Be 0
            $record.Reinstalled | Should -Be 0
            $record.Attempted | Should -Be 1
            $record.Apps[0].Outcome | Should -Be 'Failed'
            ($record.Details -join ' ') | Should -Match 'not registered for the signed-in user in the independent check'
            Should -Invoke Get-AppxPackage -ParameterFilter { $User -ceq 'S-1-5-21-100-200-300-1001' -and $Name -ceq 'Microsoft.XboxApp' }
        }
    }

    It 'keeps a reported recovery that the independent check confirms' {
        InModuleScope Privacy {
            Mock Get-AppxPackage { [pscustomobject]@{ Name = 'Microsoft.XboxApp'; PackageFamilyName = 'Microsoft.XboxApp_8wekyb3d8bbwe' } }
            $apps = @((New-AppRecoveryRequestFixture).Apps)
            $record = Confirm-PrivacyDesktopUserAppRecovery -Record (New-AppRecoveryResultFixture) -MissingApps $apps -UserSid 'S-1-5-21-100-200-300-1001'
            $record.Success | Should -BeTrue
            $record.RegisteredLocally | Should -Be 1
        }
    }

    It 'runs the worker on its pinned request and writes a result the caller accepts' {
        $exchange = Join-Path $TestDrive ('AppRecoveryWorker_' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $exchange
        InModuleScope Privacy -Parameters @{ Exchange = $exchange } {
            param($Exchange)
            Mock Assert-PrivacyAppRecoveryUserContext { }
            Mock Invoke-PrivacyAppRecoveryLoop {
                foreach ($app in $MissingApps) {
                    $Result.Attempted++; $Result.Reinstalled++; $Result.RegisteredLocally++
                    $Result.Details.Add("$($app.AppName): re-registered")
                    $Result.AppOutcomes.Add([pscustomobject]@{ AppName = [string]$app.AppName; Outcome = 'RegisteredLocally' })
                }
            }
            $requestPath = Join-Path $Exchange 'request.json'
            $resultPath = Join-Path $Exchange 'result.json'
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject (New-AppRecoveryRequestFixture) -Depth 6 -Compress))
            [IO.File]::WriteAllBytes($requestPath, $bytes)
            [IO.File]::WriteAllBytes($resultPath, [byte[]]@())
            $digest = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()

            $returned = Invoke-PrivacyAppRecoveryWorker -ExpectedSid 'S-1-5-21-100-200-300-1001' -ExpectedSessionId 1 `
                -RequestPath $requestPath -RequestSha256 $digest -OutputPath $resultPath
            $returned.Success | Should -BeTrue -Because $returned.Error
            $written = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
            { Assert-PrivacyAppRecoveryWorkerResult -Record $written -UserSid 'S-1-5-21-100-200-300-1001' -SessionId 1 -AppNames @('Microsoft.XboxApp') } |
                Should -Not -Throw
            $written.RegisteredLocally | Should -Be 1

            # Positive control: a request that no longer matches its pinned
            # digest is refused before any recovery runs.
            $tampered = [Text.UTF8Encoding]::new($false).GetBytes(([Text.Encoding]::UTF8.GetString($bytes)).Replace('9MV0B5HZVK9Z', '9MV0B5HZVK9A'))
            [IO.File]::WriteAllBytes($requestPath, $tampered)
            $refused = Invoke-PrivacyAppRecoveryWorker -ExpectedSid 'S-1-5-21-100-200-300-1001' -ExpectedSessionId 1 `
                -RequestPath $requestPath -RequestSha256 $digest -OutputPath $resultPath
            $refused.Success | Should -BeFalse
            $refused.Error | Should -Match 'pinned SHA-256'
            Should -Invoke Invoke-PrivacyAppRecoveryLoop -Times 1 -Exactly
            $rejected = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
            { Assert-PrivacyAppRecoveryWorkerResult -Record $rejected -UserSid 'S-1-5-21-100-200-300-1001' -SessionId 1 -AppNames @('Microsoft.XboxApp') } |
                Should -Throw '*worker failed: *pinned SHA-256*'
        }
    }
}
