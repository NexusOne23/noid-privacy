#Requires -Version 5.1

<#
.SYNOPSIS
    Side-effect-free unit tests for the sealed Core rollback contract.
#>

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Core/Rollback.ps1')
    Set-Item -Path function:global:Write-Log -Value { param($Level, $Message, $Module, $Exception) $null = $Level, $Message, $Module, $Exception }
    Set-Item -Path function:global:Restore-BloatwareApps -Value {
        param([string]$SessionPath, [switch]$Confirm)
        $null = $SessionPath, $Confirm
        throw 'Restore-BloatwareApps test placeholder was not mocked'
    }
    Set-Item -Path function:global:Get-BloatwareRestoreAssessment -Value {
        param([string]$SessionPath)
        $null = $SessionPath
        throw 'Get-BloatwareRestoreAssessment test placeholder was not mocked'
    }
}

Describe 'Core session path containment' {
    It 'resolves a nested relative artifact inside the selected session' {
        $session = Join-Path $TestDrive 'Session_20260710_120000_000_deadbeef'
        $expected = [System.IO.Path]::GetFullPath((Join-Path $session 'ASR/state.json'))

        Resolve-SessionChildPath -SessionPath $session -RelativePath 'ASR/state.json' |
            Should -Be $expected
    }

    It 'rejects traversal, rooted paths and the session root itself' {
        $session = Join-Path $TestDrive 'Session_20260710_120000_000_deadbeef'

        { Resolve-SessionChildPath -SessionPath $session -RelativePath '../outside.json' } |
            Should -Throw '*escapes the selected session*'
        { Resolve-SessionChildPath -SessionPath $session -RelativePath $TestDrive } |
            Should -Throw '*non-empty relative path*'
        { Resolve-SessionChildPath -SessionPath $session -RelativePath '.' } |
            Should -Throw '*escapes the selected session*'
    }
}

Describe 'Core registry path translation' {
    It 'round-trips every supported hive with one canonical separator' {
        $cases = [ordered]@{
            'HKLM:\SOFTWARE\NoID' = 'HKEY_LOCAL_MACHINE\SOFTWARE\NoID'
            'HKCU:\Software\NoID' = 'HKEY_CURRENT_USER\Software\NoID'
            'HKCR:\NoID.Handler' = 'HKEY_CLASSES_ROOT\NoID.Handler'
            'HKU:\S-1-5-21-1-2-3-1001\Software\NoID' = 'HKEY_USERS\S-1-5-21-1-2-3-1001\Software\NoID'
            'HKCC:\Software\NoID' = 'HKEY_CURRENT_CONFIG\Software\NoID'
        }

        foreach ($providerPath in $cases.Keys) {
            ConvertTo-NativeRegistryPath -Path $providerPath | Should -Be $cases[$providerPath]
            ConvertFrom-NativeRegistryPath -Path $cases[$providerPath] | Should -Be $providerPath
        }
    }

    It 'rejects ambiguous separators, wildcards, trailing separators and unsupported roots' {
        foreach ($invalidPath in @(
                'HKLM:\SOFTWARE\\NoID',
                'HKLM:\SOFTWARE/NoID',
                'HKLM:\SOFTWARE\NoID\',
                'HKLM:\SOFTWARE\NoID\*',
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\NoID'
            )) {
            { ConvertTo-NativeRegistryPath -Path $invalidPath } | Should -Throw
        }

        foreach ($invalidPath in @(
                'HKEY_LOCAL_MACHINE\SOFTWARE\\NoID',
                'HKEY_LOCAL_MACHINE\SOFTWARE/NoID',
                'HKEY_LOCAL_MACHINE\SOFTWARE\NoID\',
                'HKEY_LOCAL_MACHINE\SOFTWARE\NoID\*',
                'HKLM\SOFTWARE\NoID'
            )) {
            { ConvertFrom-NativeRegistryPath -Path $invalidPath } | Should -Throw
        }
    }

    It 'does not reinterpret a root-like name inside a valid subkey path' {
        ConvertFrom-NativeRegistryPath -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\HKEY_USERS' |
            Should -Be 'HKLM:\SOFTWARE\HKEY_USERS'
    }
}

Describe 'Core restore output contract' {
    BeforeEach {
        Mock Write-Log { }
    }

    It 'returns the one authoritative Boolean even if diagnostic text reached the pipeline' {
        Mock Invoke-RestoreSessionInternal { 'diagnostic'; $true }

        Restore-Session -SessionPath 'unused-by-mock' -NoReboot | Should -BeTrue
    }

    It 'propagates an authoritative restore failure' {
        Mock Invoke-RestoreSessionInternal { $false }

        Restore-Session -SessionPath 'unused-by-mock' -NoReboot | Should -BeFalse
    }

    It 'fails closed when no Boolean or multiple Booleans are emitted' {
        Mock Invoke-RestoreSessionInternal { 'diagnostic only' }
        Restore-Session -SessionPath 'unused-by-mock' -NoReboot | Should -BeFalse

        Mock Invoke-RestoreSessionInternal { $false; $true }
        Restore-Session -SessionPath 'unused-by-mock' -NoReboot | Should -BeFalse
    }

    It 'propagates Restore-Session failure through Restore-AllBackups' {
        $session = Join-Path $TestDrive 'Session_20260710_120000_000_deadbeef'
        $null = New-Item -Path $session -ItemType Directory -Force
        $global:BackupBasePath = $session
        Mock Restore-Session { $false }

        Restore-AllBackups -NoReboot | Should -BeFalse
        Should -Invoke Restore-Session -Times 1 -Exactly -ParameterFilter {
            $SessionPath -eq $session -and $NoReboot
        }
    }
}

Describe 'Core canonical bloatware reinstall offer' {
    BeforeEach {
        $script:OfferManifest = [PSCustomObject]@{
            modules = @([PSCustomObject]@{
                    name = 'Privacy'
                    artifacts = @([PSCustomObject]@{
                            type = 'Privacy'
                            name = 'Privacy_BloatwareActions'
                            relativePath = 'Privacy/Privacy_BloatwareActions.json'
                        })
                })
        }
        Mock Write-Host { }
        Mock Write-Log { }
        Mock Write-RestoreLog { }
        Mock Import-Module { }
        # Mirror the complete closed Get-BloatwareRestoreAssessment result contract.
        # Build-Release.ps1 runs this suite under Set-StrictMode -Version Latest,
        # where a partial mock makes the offer's summary interpolation throw.
        Mock Get-BloatwareRestoreAssessment {
            [PSCustomObject]@{
                Success = $true; Status = 'Needed'; Error = ''
                SessionPath = ''; OriginalUserSid = ''; CurrentUserSid = ''
                RecordedPresent = 3; Tier1RecordedPresent = 0; Tier2RecordedPresent = 3
                Mapped = 3; LocalRegisterable = 2; StoreMapped = 3; Missing = 2
                AlreadyPresent = 1; Unmapped = 0
                MissingApps = @(); AlreadyPresentApps = @(); UnmappedApps = @()
                Details = @()
            }
        }
    }

    It 'prompts and invokes the verified reinstall for a direct interactive Privacy restore' {
        Mock Read-Host { 'Y' }
        Mock Restore-BloatwareApps {
            [PSCustomObject]@{
                Success = $true; Status = 'Completed'; Reinstalled = 2
                AlreadyPresent = 1; Failed = 0; Skipped = 0; Details = @()
            }
        }

        $null = Invoke-RestoreBloatwareReinstallOffer `
            -SessionPath $script:RepoRoot `
            -Manifest $script:OfferManifest `
            -RestoredModuleNames @('Privacy')

        Should -Invoke Read-Host -Times 1 -Exactly
        Should -Invoke Restore-BloatwareApps -Times 1 -Exactly -ParameterFilter {
            $SessionPath -eq $script:RepoRoot -and -not $Confirm
        }
    }

    It 'uses default No and never starts winget work when the offer is declined' {
        Mock Read-Host { '' }
        Mock Restore-BloatwareApps { throw 'must not be called' }

        $null = Invoke-RestoreBloatwareReinstallOffer `
            -SessionPath $script:RepoRoot `
            -Manifest $script:OfferManifest `
            -RestoredModuleNames @('Privacy')

        Should -Invoke Read-Host -Times 1 -Exactly
        Should -Invoke Restore-BloatwareApps -Times 0 -Exactly
    }

    It 'does not prompt when every mapped app is already registered' {
        Mock Read-Host { throw 'must not be called' }
        Mock Restore-BloatwareApps { throw 'must not be called' }
        Mock Get-BloatwareRestoreAssessment {
            [PSCustomObject]@{
                Success = $true; Status = 'NothingToDo'; Error = ''
                SessionPath = ''; OriginalUserSid = ''; CurrentUserSid = ''
                RecordedPresent = 3; Tier1RecordedPresent = 0; Tier2RecordedPresent = 3
                Mapped = 3; LocalRegisterable = 3; StoreMapped = 3; Missing = 0
                AlreadyPresent = 3; Unmapped = 0
                MissingApps = @(); AlreadyPresentApps = @(); UnmappedApps = @()
                Details = @()
            }
        }

        $null = Invoke-RestoreBloatwareReinstallOffer `
            -SessionPath $script:RepoRoot `
            -Manifest $script:OfferManifest `
            -RestoredModuleNames @('Privacy')

        Should -Invoke Get-BloatwareRestoreAssessment -Times 1 -Exactly
        Should -Invoke Read-Host -Times 0 -Exactly
        Should -Invoke Restore-BloatwareApps -Times 0 -Exactly
    }

    It 'never prompts automation or a partial restore that excludes Privacy' {
        Mock Read-Host { throw 'must not be called' }
        Mock Restore-BloatwareApps { throw 'must not be called' }

        $null = Invoke-RestoreBloatwareReinstallOffer `
            -SessionPath $script:RepoRoot `
            -Manifest $script:OfferManifest `
            -RestoredModuleNames @('Privacy') `
            -SuppressPrompt
        $null = Invoke-RestoreBloatwareReinstallOffer `
            -SessionPath $script:RepoRoot `
            -Manifest $script:OfferManifest `
            -RestoredModuleNames @('ASR')

        Should -Invoke Read-Host -Times 0 -Exactly
        Should -Invoke Restore-BloatwareApps -Times 0 -Exactly
        Should -Invoke Get-BloatwareRestoreAssessment -Times 0 -Exactly
    }
}

Describe 'Core sealed multi-module manifest filtering' {
    BeforeEach {
        Mock Assert-AllowedModuleArtifact { }
        Mock Assert-ArtifactContentBinding { }
    }

    It 'accepts a sealed multi-module session when full restore omits the optional module filter' {
        $sessionId = 'Session_20260712_035112_343_b1321e36'
        $sessionPath = Join-Path $TestDrive $sessionId
        $null = New-Item -Path $sessionPath -ItemType Directory -Force
        '{}' | Set-Content -LiteralPath (Join-Path $sessionPath 'manifest.json') -Encoding UTF8

        $moduleSpecs = @(
            [PSCustomObject]@{ Name = 'DNS'; ArtifactName = 'DNS_PreState'; Type = 'DNS' }
            [PSCustomObject]@{ Name = 'ASR'; ArtifactName = 'ASR_ActiveConfiguration'; Type = 'ASR' }
        )
        $modules = foreach ($spec in $moduleSpecs) {
            $modulePath = Join-Path $sessionPath $spec.Name
            $null = New-Item -Path $modulePath -ItemType Directory -Force
            $artifactPath = Join-Path $modulePath 'state.json'
            '{}' | Set-Content -LiteralPath $artifactPath -Encoding UTF8
            [PSCustomObject]@{
                name          = $spec.Name
                backupPath    = $spec.Name
                status        = 'Success'
                itemsBackedUp = 1
                timestamp     = '2026-07-12T03:51:12.3430000+02:00'
                artifacts     = @([PSCustomObject]@{
                        type         = $spec.Type
                        name         = $spec.ArtifactName
                        target       = $spec.ArtifactName
                        relativePath = "$($spec.Name)/state.json"
                        sha256       = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash
                    })
            }
        }
        $manifest = [PSCustomObject]@{
            schemaVersion   = 2
            sessionId       = $sessionId
            displayName     = 'Backup: DNS, ASR'
            sessionType     = 'manual'
            timestamp       = '2026-07-12T03:51:12.3430000+02:00'
            frameworkVersion = '2.2.5'
            modules         = @($modules)
            sharedArtifacts = @()
            totalItems      = 2
            restorable      = $true
        }

        { Assert-SessionManifest -SessionPath $sessionPath -Manifest $manifest } |
            Should -Not -Throw
    }
}

Describe 'Core typed-artifact content binding' {
    It 'validates canonical SecurityTemplate targets when GPO objects omit optional sections' {
        $targetPath = Join-Path $script:RepoRoot 'Modules/SecurityBaseline/ParsedSettings/SecurityTemplates.json'
        $targets = Get-Content -LiteralPath $targetPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $names = @{
            'System Access' = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            'Privilege Rights' = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        }
        foreach ($gpo in $targets.PSObject.Properties) {
            foreach ($sectionName in $names.Keys) {
                $property = $gpo.Value.PSObject.Properties[$sectionName]
                if ($null -eq $property) { continue }
                foreach ($name in $property.Value.PSObject.Properties.Name) {
                    $null = $names[$sectionName].Add([string]$name)
                }
            }
        }
        $infPath = Join-Path $TestDrive 'SecurityTemplate.inf'
        $lines = @('[Unicode]', 'Unicode=yes', '', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '')
        foreach ($sectionName in @('System Access', 'Privilege Rights')) {
            $lines += "[$sectionName]"
            $lines += @($names[$sectionName] | ForEach-Object { "$_ =" })
            $lines += ''
        }
        $lines | Set-Content -LiteralPath $infPath -Encoding Unicode

        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'SecurityBaseline'; name = 'SecurityTemplate'; target = 'SecurityTemplate'
                }) -ArtifactPath $infPath } | Should -Not -Throw
    }

    It 'accepts only registry headers contained below the sealed target' {
        $validPath = Join-Path $TestDrive 'valid.reg'
        $invalidPath = Join-Path $TestDrive 'invalid.reg'
        @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\NoID]'
            '[HKEY_LOCAL_MACHINE\SOFTWARE\NoID\Child]'
        ) | Set-Content -LiteralPath $validPath -Encoding Unicode
        @(
            'Windows Registry Editor Version 5.00'
            ''
            '[HKEY_LOCAL_MACHINE\SOFTWARE\NoID]'
            '[HKEY_LOCAL_MACHINE\SOFTWARE\Outside]'
        ) | Set-Content -LiteralPath $invalidPath -Encoding Unicode
        $artifact = [PSCustomObject]@{ type = 'Registry'; target = 'HKLM:\SOFTWARE\NoID' }

        { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $validPath } |
            Should -Not -Throw
        { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $invalidPath } |
            Should -Throw '*outside manifest target*'
    }

    It 'binds empty-marker, service and scheduled-task identities to the manifest target' {
        $markerPath = Join-Path $TestDrive 'marker.json'
        $servicePath = Join-Path $TestDrive 'service.json'
        $taskPath = Join-Path $TestDrive 'task.json'
        [PSCustomObject]@{
            SchemaVersion = 2; State = 'NotExisted'; KeyPath = 'HKLM:\SOFTWARE\NoID'
        } | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
        [PSCustomObject]@{
            SchemaVersion = 2; Name = 'DiagTrack'; StartType = 'Disabled'; Status = 'Stopped'
            RestoreRuntimeState = $true; DelayedAutoStartExists = $false
            DelayedAutoStart = $null; DelayedAutoStartType = $null
        } | ConvertTo-Json | Set-Content -LiteralPath $servicePath -Encoding UTF8
        [PSCustomObject]@{
            SchemaVersion = 2; TaskPath = '\Microsoft\Windows\NoID\'; TaskName = 'Task'
            XmlDefinition = '<Task><RegistrationInfo><URI>\Microsoft\Windows\NoID\Task</URI></RegistrationInfo></Task>'
        } | ConvertTo-Json | Set-Content -LiteralPath $taskPath -Encoding UTF8

        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'EmptyMarker'; target = 'HKLM:\SOFTWARE\NoID'
                }) -ArtifactPath $markerPath } | Should -Not -Throw
        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'Service'; target = 'DiagTrack'
                }) -ArtifactPath $servicePath } | Should -Not -Throw
        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'ScheduledTask'; target = '\Microsoft\Windows\NoID\Task'
                }) -ArtifactPath $taskPath } | Should -Not -Throw
        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'Service'; target = 'OtherService'
                }) -ArtifactPath $servicePath } | Should -Throw '*does not match manifest target*'
    }

    It 'validates current schema-2 and legacy flat NetBIOS adapter artifacts' {
        $artifact = [PSCustomObject]@{
            type = 'AdvancedSecurity'; name = 'NetBIOS_Adapters'; target = 'NetBIOS_Adapters'
        }
        $settingId = '{11111111-1111-1111-1111-111111111111}'
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$settingId"
        $schema2Path = Join-Path $TestDrive 'netbios-schema2.json'
        [PSCustomObject]@{
            SchemaVersion = 2
            Adapters = @([PSCustomObject]@{
                    SettingID = $settingId
                    IPEnabled = $false
                    PhysicalAdapter = $true
                    RegistryPath = $registryPath
                    RegistryKeyExisted = $true
                    RegistryValueExists = $true
                    RegistryValueType = 'DWord'
                    RegistryValue = 0
                })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $schema2Path -Encoding UTF8

        $legacyPath = Join-Path $TestDrive 'netbios-schema1.json'
        ConvertTo-Json -InputObject @([PSCustomObject]@{
                SettingID = $settingId
                TcpipNetbiosOptions = 0
            }) | Set-Content -LiteralPath $legacyPath -Encoding UTF8

        { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $schema2Path } |
            Should -Not -Throw
        { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $legacyPath } |
            Should -Not -Throw
    }

    It 'rejects a schema-2 NetBIOS envelope without its adapter inventory' {
        $artifactPath = Join-Path $TestDrive 'netbios-schema2-missing-adapters.json'
        [PSCustomObject]@{ SchemaVersion = 2 } |
            ConvertTo-Json | Set-Content -LiteralPath $artifactPath -Encoding UTF8

        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'AdvancedSecurity'; name = 'NetBIOS_Adapters'; target = 'NetBIOS_Adapters'
                }) -ArtifactPath $artifactPath } |
            Should -Throw '*must use schema version 2*'
    }

    It 'serializes service status and startup enums by stable names' {
        $source = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'Status\s*=\s*\[string\]\$service\.Status'
        $source | Should -Match 'StartType\s*=\s*\[string\]\$service\.StartType'
    }

    It 'orders sealed service restore artifacts dependency-first' {
        Mock Get-Service {
            if ($Name -eq 'FDResPub') {
                return [PSCustomObject]@{
                    Name = 'FDResPub'
                    ServicesDependedOn = @([PSCustomObject]@{ Name = 'fdPHost' })
                }
            }
            if ($Name -eq 'fdPHost') {
                return [PSCustomObject]@{
                    Name = 'fdPHost'
                    ServicesDependedOn = @()
                }
            }
            throw "Unexpected service identity: $Name"
        }

        $artifacts = @(
            [PSCustomObject]@{ type = 'Service'; target = 'FDResPub' }
            [PSCustomObject]@{ type = 'Service'; target = 'fdPHost' }
        )
        $ordered = @(Get-ServiceArtifactsInRestoreOrder -Artifacts $artifacts)

        (@($ordered.target) -join ',') | Should -Be 'fdPHost,FDResPub'
        Should -Invoke Get-Service -Times 2 -Exactly
    }

    It 'fails closed on a cyclic sealed service dependency inventory' {
        Mock Get-Service {
            $otherName = if ($Name -eq 'ServiceA') { 'ServiceB' } else { 'ServiceA' }
            [PSCustomObject]@{
                Name = $Name
                ServicesDependedOn = @([PSCustomObject]@{ Name = $otherName })
            }
        }

        $artifacts = @(
            [PSCustomObject]@{ type = 'Service'; target = 'ServiceA' }
            [PSCustomObject]@{ type = 'Service'; target = 'ServiceB' }
        )

        { Get-ServiceArtifactsInRestoreOrder -Artifacts $artifacts } |
            Should -Throw '*Cyclic sealed service dependency*'
    }

    It 'rejects duplicate or unsupported ASR rule state' {
        $asrPath = Join-Path $TestDrive 'asr.json'
        $guid = '56a863a9-875e-4185-98a7-b882c64b5ce5'
        [PSCustomObject]@{
            SchemaVersion = 3
            Target = 'WindowsClientDefenderASR'
            PolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            PolicyKeyExisted = $false
            DeclaredCount = 2
            TargetCount = 2
            NotApplicableCount = 0
            NotApplicable = @()
            Targets = @(
                [PSCustomObject]@{
                    Name = 'Rule A'; GUID = $guid; RequestedAction = 1
                    OriginalExists = $false; OriginalAction = $null
                    PolicyOverride = $false; UserConfigurable = $false
                    BaselineStatus = 'Block'; PolicyValue = $null
                }
                [PSCustomObject]@{
                    Name = 'Rule B'; GUID = $guid; RequestedAction = 6
                    OriginalExists = $false; OriginalAction = $null
                    PolicyOverride = $false; UserConfigurable = $false
                    BaselineStatus = 'Block'; PolicyValue = $null
                }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $asrPath -Encoding UTF8

        { Assert-ArtifactContentBinding -Artifact ([PSCustomObject]@{
                    type = 'ASR'; target = 'DefenderASR'
                }) -ArtifactPath $asrPath } | Should -Throw '*invalid or duplicate target*'
    }
}

Describe 'Core backup sealing failure behavior' {
    BeforeEach {
        Mock Write-Log { }
        $session = Join-Path $TestDrive 'Session_20260710_120000_000_deadbeef'
        $null = New-Item -Path (Join-Path $session 'ASR') -ItemType Directory -Force
        $global:BackupBasePath = $session
        $global:CurrentModule = 'ASR'
        $global:BackupIndex = @()
        $global:SessionManifest = @{
            schemaVersion = 2; modules = @(); totalItems = 0; restorable = $true
        }
    }

    It 'refuses a partial backup whose declared item count exceeds its artifacts' {
        $artifactPath = Join-Path $global:BackupBasePath 'ASR/state.json'
        '{}' | Set-Content -LiteralPath $artifactPath -Encoding UTF8
        $global:BackupIndex = @([PSCustomObject]@{
                Module = 'ASR'; Type = 'ASR'; Name = 'ASR_ActiveConfiguration'
                Path = 'DefenderASR'; BackupFile = $artifactPath
            })

        Complete-ModuleBackup -ItemsBackedUp 2 -Status Success | Should -BeFalse
        @($global:SessionManifest.modules).Count | Should -Be 0
        [string]$global:CurrentModule | Should -Be 'ASR'
    }

    It 'refuses to seal an artifact located outside the selected session' {
        $artifactPath = Join-Path $TestDrive 'outside.json'
        '{}' | Set-Content -LiteralPath $artifactPath -Encoding UTF8
        $global:BackupIndex = @([PSCustomObject]@{
                Module = 'ASR'; Type = 'ASR'; Name = 'ASR_ActiveConfiguration'
                Path = 'DefenderASR'; BackupFile = $artifactPath
            })

        Complete-ModuleBackup -ItemsBackedUp 1 -Status Success | Should -BeFalse
        @($global:SessionManifest.modules).Count | Should -Be 0
    }
}
