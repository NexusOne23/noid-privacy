#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/Privacy/Privacy.psm1') -Force
    InModuleScope Privacy {
        # Real inventory validators and public recovery functions; session transport and
        # Windows deployment are isolated. These fixtures are not package-install evidence.
        function script:Get-SessionRestoreReceipt { param($SessionPath) $null = $SessionPath }
        function script:Get-SessionManifest { param($SessionPath) $null = $SessionPath }
        function script:Assert-SessionManifest { param($SessionPath,$Manifest,$RequestedModules) $null = $SessionPath,$Manifest,$RequestedModules }
        function script:Resolve-SessionChildPath { param($SessionPath,$RelativePath) $null = $SessionPath,$RelativePath }
        function script:Write-Log { param($Level,$Message,$Module) $null = $Level,$Message,$Module }

        function script:New-NewsEntry {
            param([string]$AppName, [object]$Mapping, [bool]$Present)
            $family = if ($Present) { "${AppName}_8wekyb3d8bbwe" } else { $null }
            [pscustomobject]@{
                AppName = $AppName; Present = $Present
                PackageFullName = if ($Present) { "${AppName}_1.0.0.0_x64__8wekyb3d8bbwe" } else { $null }
                PackageFamilyName = $family
                Version = if ($Present) { '1.0.0.0' } else { $null }
                ProvisionedPackageNames = @()
                StoreId = [string]$Mapping.StoreId
                ExpectedPackageNames = @($Mapping.ExpectedPackageNames)
            }
        }

        # Writes the sealed inventories of one session: Tier 1 and/or Tier 2, with only one app (News) present.
        function script:New-NewsSessionFixture {
            param([bool]$Tier1, [bool]$Tier2, [string]$Contract = 'Current', [string]$PresentApp = 'Microsoft.BingNews')
            $artifacts = [Collections.Generic.List[object]]::new()
            $sid = 'S-1-5-21-100-200-300-1001'
            if ($Tier1) {
                $catalog = switch ($Contract) {
                    'PreviousV34' { Get-PrivacyTier1AppCatalog -PreviousV34 }
                    'PreviousV35' { Get-PrivacyTier1AppCatalog -PreviousV35 }
                    default { Get-PrivacyTier1AppCatalog }
                }
                $entries = @($catalog.Apps | ForEach-Object { New-NewsEntry -AppName $_.AppName -Mapping $_ -Present ($_.AppName -ceq $PresentApp) })
                $inventory = [pscustomobject]@{
                    SchemaVersion = 1; Mode = 'tier1-policy'; InteractiveUserSid = $sid
                    Timestamp = [DateTime]::UtcNow.ToString('o')
                    PolicySha256 = [string]$catalog.PolicySha256; CatalogSha256 = [string]$catalog.CatalogSha256
                    InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entries; Entries = $entries
                }
                $null = Assert-PrivacyTier1AppInventory -Inventory $inventory
                $inventory | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:NewsSession 'Privacy/Privacy_Tier1AppInventory.json') -Encoding UTF8
                $artifacts.Add([pscustomobject]@{ type='Privacy'; name='Privacy_Tier1AppInventory'; relativePath='Privacy/Privacy_Tier1AppInventory.json' })
            }
            if ($Tier2) {
                $config = switch ($Contract) {
                    'PreviousV34' { Get-PrivacyBloatwareConfig -PreviousV34 }
                    'PreviousV35' { Get-PrivacyBloatwareConfig -PreviousV35 }
                    default { Get-PrivacyBloatwareConfig }
                }
                $entries = @($config.RemoveApps | ForEach-Object { New-NewsEntry -AppName $_ -Mapping $config.Mappings.$_ -Present ($_ -ceq $PresentApp) })
                $log = [pscustomobject]@{
                    SchemaVersion = 3; Mode = 'standard'; WeatherWidgetRemovalSelected = $false; InteractiveUserSid = $sid
                    Timestamp = [DateTime]::UtcNow.ToString('o'); CatalogSha256 = [string]$config.CatalogSha256
                    InventorySha256 = Get-PrivacyBloatwareInventoryFingerprint -Entries $entries; Entries = $entries
                }
                $null = Assert-PrivacyBloatwareActionLog -ActionLog $log
                $log | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:NewsSession 'Privacy/Privacy_BloatwareActions.json') -Encoding UTF8
                $artifacts.Add([pscustomobject]@{ type='Privacy'; name='Privacy_BloatwareActions'; relativePath='Privacy/Privacy_BloatwareActions.json' })
            }
            $script:NewsArtifacts = @($artifacts)
        }
    }
}

AfterAll {
    Remove-Module Privacy -Force
}

Describe 'News comes back from the Store only after Tier 1 removed it for the whole device' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $session = Join-Path $TestDrive ('Session_News_' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -Path (Join-Path $session 'Privacy') -ItemType Directory -Force
        InModuleScope Privacy -Parameters @{ Session = $session } {
            param($Session)
            $script:NewsSession = $Session
            $script:RegisteredApps = @{}
            # 'DeviceWide': Tier 1 deprovisioned the package, so re-registration fails like
            # Windows does (0x80073CF9). 'Staged': the package is still on the device (Tier 2).
            $script:PackageState = 'DeviceWide'
            $script:RecoveryEvents = [Collections.Generic.List[string]]::new()
            Mock Test-NoIDNetworkConnection { $true }
            Mock Get-PrivacyCurrentProcessUserSid { 'S-1-5-21-100-200-300-1001' }
            Mock Get-SessionManifest { [pscustomobject]@{ modules = @([pscustomobject]@{ name='Privacy'; artifacts=$script:NewsArtifacts }) } }
            Mock Assert-SessionManifest { }
            Mock Resolve-SessionChildPath { Join-Path $script:NewsSession $RelativePath }
            Mock Get-AppxPackage { if ($script:RegisteredApps.ContainsKey($Name)) { $script:RegisteredApps[$Name] } }
            Mock Add-AppxPackage {
                $script:RecoveryEvents.Add("register:$MainPackage")
                if ($script:PackageState -ceq 'DeviceWide') {
                    throw 'Deployment failed with HRESULT: 0x80073CF9, Install failed. Please contact your software vendor.'
                }
                $script:RegisteredApps['Microsoft.BingNews'] = [pscustomobject]@{ Name='Microsoft.BingNews';PackageFamilyName=$MainPackage }
            }
            Mock Get-Command { [pscustomobject]@{ Path=$env:ComSpec;Source=$env:ComSpec } } -ParameterFilter { $Name -eq 'winget' }
            Mock Invoke-PrivacyBoundedProcess {
                $script:RecoveryEvents.Add(([string]$ArgumentList[0]) + ':' + [string]$ArgumentList[2])
                if ($ArgumentList[0] -ceq 'install') {
                    if ($script:PackageState -ceq 'Staged') { return -2147009285 }  # 0x80073CFB
                    $installed = @{ '9WZDNCRFHVFW'='Microsoft.BingNews'; '9WZDNCRD1HKW'='Microsoft.XboxIdentityProvider'; '9NKNC0LD5NN6'='Microsoft.Xbox.TCUI' }[[string]$ArgumentList[2]]
                    if ($installed) { $script:RegisteredApps[$installed] = [pscustomobject]@{ Name=$installed;PackageFamilyName="${installed}_8wekyb3d8bbwe" } }
                }
                0
            }
            Mock Update-PrivacyWinGet { throw 'not expected' }
        }
    }

    It 'maps News to the Store only in the Tier 1 catalog' {
        InModuleScope Privacy {
            $tier2 = (Get-PrivacyBloatwareConfig).Mappings.'Microsoft.BingNews'
            [string]$tier2.StoreId | Should -BeExactly ''
            @($tier2.ExpectedPackageNames).Count | Should -Be 0
            [string]$tier2.DeprovisionedStoreId | Should -BeExactly '9WZDNCRFHVFW'
            $tier1 = (Get-PrivacyTier1AppCatalog).Apps | Where-Object AppName -ceq 'Microsoft.BingNews'
            [string]$tier1.StoreId | Should -BeExactly '9WZDNCRFHVFW'
            @($tier1.ExpectedPackageNames) | Should -Be @('Microsoft.BingNews')
        }
    }

    It 'removes device-wide only what recovery can bring back and games do not need: Solitaire, the Speech Window and the Xbox sign-in components stay' {
        InModuleScope Privacy {
            $catalog = Get-PrivacyTier1AppCatalog
            @($catalog.Apps.AppName | Sort-Object) | Should -Be @(
                'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.Copilot', 'Microsoft.GamingApp')
            @($catalog.Apps | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.StoreId) }).Count | Should -Be 0
            # Tier 2 still removes Solitaire for the user, but no longer the Xbox components.
            $tier2 = Get-PrivacyBloatwareConfig
            $tier2.RemoveApps | Should -Contain 'Microsoft.MicrosoftSolitaireCollection'
            foreach ($kept in @('Microsoft.XboxSpeechToTextOverlay', 'Microsoft.XboxIdentityProvider', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxGamingOverlay')) {
                $tier2.RemoveApps | Should -Not -Contain $kept
            }
            # Sessions sealed by 2.2.6 to the 2.3.0 candidates keep six apps and the
            # device-wide TCUI Store route; the current map keeps that route for them.
            $v35 = Get-PrivacyTier1AppCatalog -PreviousV35
            @($v35.Apps.AppName | Sort-Object) | Should -Be @(
                'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.Copilot',
                'Microsoft.GamingApp', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxIdentityProvider')
            $tcui = $v35.Apps | Where-Object AppName -ceq 'Microsoft.Xbox.TCUI'
            [string]$tcui.StoreId | Should -BeExactly '9NKNC0LD5NN6'
            @($tcui.ExpectedPackageNames) | Should -Be @('Microsoft.Xbox.TCUI')
            $recovery = $tier2.RecoveryMappings.'Microsoft.Xbox.TCUI'
            [string]$recovery.StoreId | Should -BeExactly ''
            @($recovery.ExpectedPackageNames).Count | Should -Be 0
            [string]$recovery.DeprovisionedStoreId | Should -BeExactly '9NKNC0LD5NN6'
            [string]$tier2.RecoveryMappings.'Microsoft.XboxIdentityProvider'.StoreId | Should -BeExactly '9WZDNCRD1HKW'
            # Sessions sealed by earlier builds keep their eight apps and local-only TCUI route.
            $v34 = Get-PrivacyTier1AppCatalog -PreviousV34
            @($v34.Apps).Count | Should -Be 8
            [string]($v34.Apps | Where-Object AppName -ceq 'Microsoft.Xbox.TCUI').StoreId | Should -BeExactly ''
        }
    }

    It 'v3.5 Tier 1 session: <App> comes back from the Store through the recovery-only route' -ForEach @(
        @{ App='Microsoft.XboxIdentityProvider'; StoreId='9WZDNCRD1HKW' }, @{ App='Microsoft.Xbox.TCUI'; StoreId='9NKNC0LD5NN6' }
    ) {
        InModuleScope Privacy -Parameters @{ App=$App; StoreId=$StoreId } {
            param($App, $StoreId)
            New-NewsSessionFixture -Tier1 $true -Tier2 $false -Contract 'PreviousV35' -PresentApp $App
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $missing = @($assessment.MissingApps | Where-Object AppName -ceq $App)
            $missing.Count | Should -Be 1
            $missing[0].CanUseStore | Should -BeTrue
            $missing[0].StoreId | Should -BeExactly $StoreId
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.InstalledFromStore | Should -Be 1
            $script:RecoveryEvents | Should -Contain "install:$StoreId"
        }
    }

    It 'Tier 1 + Tier 2: local re-registration fails, the Store install brings News back' {
        InModuleScope Privacy {
            New-NewsSessionFixture -Tier1 $true -Tier2 $true
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $news = @($assessment.MissingApps | Where-Object AppName -ceq 'Microsoft.BingNews')
            $news.Count | Should -Be 1
            $news[0].CanUseStore | Should -BeTrue
            $news[0].StoreId | Should -BeExactly '9WZDNCRFHVFW'
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.InstalledFromStore | Should -Be 1
            $result.RegisteredLocally | Should -Be 0
            # Local first, Store only after the local route failed.
            @($script:RecoveryEvents | Where-Object { $_ -like 'register:*' -or $_ -like 'install:*' }) |
                Should -Be @('register:Microsoft.BingNews_8wekyb3d8bbwe', 'install:9WZDNCRFHVFW')
        }
    }

    It 'Tier 1 alone carries the same Store route' {
        InModuleScope Privacy {
            New-NewsSessionFixture -Tier1 $true -Tier2 $false
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.InstalledFromStore | Should -Be 1
        }
    }

    It 'Tier 2 alone keeps the local re-registration and never calls the Store' {
        InModuleScope Privacy {
            $script:PackageState = 'Staged'
            New-NewsSessionFixture -Tier1 $false -Tier2 $true
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            @($assessment.MissingApps | Where-Object AppName -ceq 'Microsoft.BingNews')[0].CanUseStore | Should -BeFalse
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.RegisteredLocally | Should -Be 1
            $result.InstalledFromStore | Should -Be 0
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly
        }
    }

    It 'Tier 2 alone reports a failed local route without trying the Store' {
        InModuleScope Privacy {
            New-NewsSessionFixture -Tier1 $false -Tier2 $true
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeFalse
            $result.Failed | Should -Be 1
            ($result.Details -join ' ') | Should -Match 'Microsoft\.BingNews: local recovery failed and no verified Store fallback exists'
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 0 -Exactly
        }
    }

    It 'a v3.4 Tier 1 session stays restorable and still tries the local route first' {
        InModuleScope Privacy {
            $script:PackageState = 'Staged'
            New-NewsSessionFixture -Tier1 $true -Tier2 $true -Contract 'PreviousV34'
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.RegisteredLocally | Should -Be 1
            $result.InstalledFromStore | Should -Be 0
        }
    }

    It 'a v3.4 Tier 1 session that sealed no Store route gets the engine route after a device-wide removal' {
        InModuleScope Privacy {
            New-NewsSessionFixture -Tier1 $true -Tier2 $true -Contract 'PreviousV34'
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            $assessment.Success | Should -BeTrue -Because $assessment.Error
            $news = @($assessment.MissingApps | Where-Object AppName -ceq 'Microsoft.BingNews')[0]
            # The route comes from the engine's own catalog, not from the session.
            $news.CanUseStore | Should -BeTrue
            $news.StoreId | Should -BeExactly '9WZDNCRFHVFW'
            @($news.ExpectedPackageNames) | Should -Be @('Microsoft.BingNews')
            $result = Restore-BloatwareApps -SessionPath $script:NewsSession -Confirm:$false
            $result.Success | Should -BeTrue -Because ($result.Details -join '; ')
            $result.InstalledFromStore | Should -Be 1
            @($script:RecoveryEvents | Where-Object { $_ -like 'register:*' -or $_ -like 'install:*' }) |
                Should -Be @('register:Microsoft.BingNews_8wekyb3d8bbwe', 'install:9WZDNCRFHVFW')
        }
    }

    It 'a v3.4 Tier 2-only session gets no engine route: its package stays staged' {
        InModuleScope Privacy {
            New-NewsSessionFixture -Tier1 $false -Tier2 $true -Contract 'PreviousV34'
            $assessment = Get-BloatwareRestoreAssessment -SessionPath $script:NewsSession
            @($assessment.MissingApps | Where-Object AppName -ceq 'Microsoft.BingNews')[0].CanUseStore | Should -BeFalse
        }
    }
}
