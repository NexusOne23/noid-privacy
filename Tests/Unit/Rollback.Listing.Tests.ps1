#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core/Rollback.ps1')
    # Restore receipts are written and validated by the Quick Action core, which
    # the shell dot-sources in the same session as Rollback.ps1.
    . (Join-Path $repoRoot 'Core/QuickActions.ps1')
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module)
        $null = $Level, $Message, $Module
    }

    function New-TestSealedModuleSession {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory = $true)]
            [string]$BackupRoot,

            [Parameter(Mandatory = $true)]
            [string[]]$ModuleNames
        )

        $sessionId = 'Session_20260712_035112_343_b1321e36'
        $sessionPath = Join-Path $BackupRoot $sessionId
        if (-not $PSCmdlet.ShouldProcess($sessionPath, 'Create sealed module test session')) {
            return
        }
        $null = New-Item -Path $sessionPath -ItemType Directory -Force

        $modules = foreach ($moduleName in $ModuleNames) {
            $modulePath = Join-Path $sessionPath $moduleName
            $null = New-Item -Path $modulePath -ItemType Directory -Force
            $artifactPath = Join-Path $modulePath 'state.json'
            '{}' | Set-Content -LiteralPath $artifactPath -Encoding UTF8
            # Assert-SessionManifest requires each module's own mandatory
            # artifact name; DNS and EdgeHardening both seal '<Module>_PreState'.
            [PSCustomObject]@{
                name          = $moduleName
                backupPath    = $moduleName
                status        = 'Success'
                itemsBackedUp = 1
                timestamp     = '2026-07-12T03:51:12.3430000+02:00'
                artifacts     = @([PSCustomObject]@{
                        type         = $moduleName
                        name         = "$($moduleName)_PreState"
                        target       = "$($moduleName)_PreState"
                        relativePath = "$moduleName/state.json"
                        sha256       = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash
                    })
            }
        }

        $manifest = [PSCustomObject]@{
            schemaVersion    = 2
            sessionId        = $sessionId
            displayName      = "Backup: $($ModuleNames -join ', ')"
            sessionType      = 'manual'
            timestamp        = '2026-07-12T03:51:12.3430000+02:00'
            frameworkVersion = '2.2.5'
            modules          = @($modules)
            sharedArtifacts  = @()
            totalItems       = $ModuleNames.Count
            restorable       = $true
        }
        $manifest |
            ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $sessionPath 'manifest.json') -Encoding UTF8

        return [PSCustomObject]@{
            SessionId   = $sessionId
            SessionPath = $sessionPath
            Manifest    = Get-SessionManifest -SessionPath $sessionPath
        }
    }
}

Describe 'Backup-session listing invariants' {
    AfterEach {
        $global:BackupIndex = @()
        $global:BackupBasePath = ''
        $global:SessionManifest = @{}
        $global:CurrentModule = ''
        Get-ChildItem -LiteralPath $TestDrive -Force -ErrorAction Stop |
            Remove-Item -Recurse -Force -ErrorAction Stop
    }

    It 'retains and lists an unsealed session as explicitly non-restorable' {
        $backupRoot = Join-Path $TestDrive 'Backups'
        $sessionId = 'Session_20260710_120000_000_abcdef12'
        $sessionPath = Join-Path $backupRoot $sessionId
        $null = New-Item -ItemType Directory -Path $sessionPath -Force

        $sessions = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue)

        $sessions.Count | Should -Be 1
        $sessions[0].SessionId | Should -Be $sessionId
        $sessions[0].Restorable | Should -BeFalse
        $sessions[0].ValidationStatus | Should -Be 'NotRestorable'
        $sessions[0].DisplayName | Should -Be 'Empty session - no backup captured'
        $sessions[0].RetentionKind | Should -Be 'EmptySession'
        $sessions[0].ValidationError | Should -Match 'no module completed Backup'
        Test-Path -LiteralPath $sessionPath -PathType Container | Should -BeTrue
    }

    It 'lists a legacy or renamed directory instead of hiding it by name' {
        $backupRoot = Join-Path $TestDrive 'Backups'
        $legacySession = Join-Path $backupRoot 'LegacyBackup-RenamedByUser'
        $null = New-Item -ItemType Directory -Path $legacySession -Force

        $sessions = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue)

        $sessions.Count | Should -Be 1
        $sessions[0].SessionId | Should -Be 'LegacyBackup-RenamedByUser'
        $sessions[0].Restorable | Should -BeFalse
        Test-Path -LiteralPath $legacySession -PathType Container | Should -BeTrue
    }

    It 'detaches, inventories, retains and lists an incomplete module backup' {
        $backupRoot = Join-Path $TestDrive 'Backups'
        $activeId = 'Session_20260710_120000_000_abcdef12'
        $activePath = Join-Path $backupRoot $activeId
        $modulePath = Join-Path $activePath 'DNS'
        $null = New-Item -ItemType Directory -Path $modulePath -Force
        $artifactPath = Join-Path $modulePath 'DNS_PreState.json'
        Set-Content -LiteralPath $artifactPath -Value '{"captured":true}' -Encoding UTF8

        $global:BackupBasePath = $activePath
        $global:SessionManifest = @{ modules = @(); restorable = $true }
        $global:CurrentModule = 'DNS'
        $global:BackupIndex = @([PSCustomObject]@{ Module = 'DNS'; BackupFile = $artifactPath })

        Save-IncompleteModuleBackup -ModuleName DNS -Confirm:$false | Should -BeTrue

        Test-Path -LiteralPath $modulePath -PathType Container | Should -BeFalse
        $global:CurrentModule | Should -Be ''
        @($global:BackupIndex).Count | Should -Be 0

        $retained = @(Get-ChildItem -LiteralPath $backupRoot -Directory -Force |
            Where-Object Name -ne $activeId)
        $retained.Count | Should -Be 1
        $retained[0].Name | Should -Match '^Session_\d{8}_\d{6}_\d{3}_[0-9a-f]{8}_Incomplete_DNS$'
        $markerPath = Join-Path $retained[0].FullName 'incomplete-backup.json'
        Test-Path -LiteralPath $markerPath -PathType Leaf | Should -BeTrue

        $marker = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $marker.recordType | Should -Be 'IncompleteModuleBackup'
        $marker.moduleName | Should -Be 'DNS'
        $marker.status | Should -Be 'IncompleteNonRestorable'
        $marker.fileCount | Should -Be 1

        $listed = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue |
            Where-Object SessionId -eq $retained[0].Name)
        $listed.Count | Should -Be 1
        $listed[0].DisplayName | Should -Be 'Incomplete backup: DNS'
        $listed[0].RetentionKind | Should -Be 'IncompleteRetained'
        $listed[0].Restorable | Should -BeFalse
        $listed[0].TotalItems | Should -Be 1
        Test-Path -LiteralPath (Join-Path $retained[0].FullName 'DNS\DNS_PreState.json') -PathType Leaf | Should -BeTrue

        Set-Content -LiteralPath (Join-Path $retained[0].FullName 'DNS\undeclared.txt') -Value 'not inventoried' -Encoding UTF8
        $tampered = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue |
            Where-Object SessionId -eq $retained[0].Name)
        $tampered.Count | Should -Be 1
        $tampered[0].RetentionKind | Should -Be 'InvalidOrUnsealed'
        $tampered[0].Restorable | Should -BeFalse
        $tampered[0].ValidationError | Should -Match 'undeclared retained file'

        Remove-Item -LiteralPath (Join-Path $retained[0].FullName 'DNS\undeclared.txt') -Force
        $null = New-Item -ItemType Directory -Path (Join-Path $retained[0].FullName 'DNS\undeclared-empty')
        $withUndeclaredDirectory = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue |
            Where-Object SessionId -eq $retained[0].Name)
        $withUndeclaredDirectory.Count | Should -Be 1
        $withUndeclaredDirectory[0].RetentionKind | Should -Be 'InvalidOrUnsealed'
        $withUndeclaredDirectory[0].ValidationError | Should -Match 'undeclared directory'
    }

    It 'derives an explicit display name from the actual sealed module set' {
        $manifest = [PSCustomObject]@{
            sessionType = 'manual'
            modules     = @(
                [PSCustomObject]@{ name = 'DNS' },
                [PSCustomObject]@{ name = 'Privacy' }
            )
        }

        Get-SessionDisplayNameValue -Manifest $manifest | Should -Be 'Backup: DNS, Privacy'
    }

    It 'atomically creates and replaces a UTF-8 trust-anchor file without stale temporary files' {
        $target = Join-Path $TestDrive 'manifest.json'

        Write-AtomicUtf8File -Path $target -Content '{"generation":1}' | Should -BeTrue
        Write-AtomicUtf8File -Path $target -Content '{"generation":2}' | Should -BeTrue

        Get-Content -LiteralPath $target -Raw -Encoding UTF8 | Should -Be '{"generation":2}'
        @(Get-ChildItem -LiteralPath $TestDrive -File -Force |
            Where-Object Name -Like 'manifest.json.*.tmp').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $TestDrive -File -Force |
            Where-Object Name -Like 'manifest.json.*.replace-backup').Count | Should -Be 0
    }

    It 'keeps a restored module session restorable and reports when it was restored' {
        Mock Assert-AllowedModuleArtifact { }
        Mock Assert-ArtifactContentBinding { }
        $backupRoot = Join-Path $TestDrive 'Backups'
        $session = New-TestSealedModuleSession -BackupRoot $backupRoot -ModuleNames @('DNS', 'EdgeHardening')

        $sealed = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue)
        $sealed.Count | Should -Be 1
        $sealed[0].Restorable | Should -BeTrue
        $sealed[0].ValidationStatus | Should -Be 'SealedAndValidated'
        $sealed[0].RetentionKind | Should -Be 'Sealed'
        $sealed[0].LastRestoredAt | Should -BeNullOrEmpty
        @($sealed[0].RestoredModules).Count | Should -Be 0
        Get-SessionRestoreHistoryText -Session $sealed[0] | Should -Be ''

        $null = Write-SessionRestoreReceipt `
            -SessionPath $session.SessionPath `
            -Manifest $session.Manifest `
            -Scopes @('module:DNS') `
            -Confirm:$false

        $partial = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue)
        $partial.Count | Should -Be 1
        $partial[0].Restorable | Should -BeTrue
        $partial[0].ValidationStatus | Should -Be 'PartiallyRestoredAndValidated'
        $partial[0].RetentionKind | Should -Be 'SealedPartiallyRestored'
        $partial[0].ValidationError | Should -Be ''
        @($partial[0].RestoredModules) | Should -Be @('DNS')
        $partial[0].LastRestoredAt | Should -BeOfType [DateTime]
        Get-SessionRestoreHistoryText -Session $partial[0] | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(DNS\)$'

        $null = Write-SessionRestoreReceipt `
            -SessionPath $session.SessionPath `
            -Manifest $session.Manifest `
            -Scopes @('module:EdgeHardening') `
            -Confirm:$false

        # A fully restored session is history, not a spent ticket: it stays
        # restorable so the same known state can be returned to again.
        $restored = @(Get-BackupSessions -BackupDirectory $backupRoot -WarningAction SilentlyContinue)
        $restored.Count | Should -Be 1
        $restored[0].Restorable | Should -BeTrue
        $restored[0].ValidationStatus | Should -Be 'RestoredAndValidated'
        $restored[0].RetentionKind | Should -Be 'SealedRestored'
        $restored[0].ValidationError | Should -Be ''
        @($restored[0].RestoredModules | Sort-Object) | Should -Be @('DNS', 'EdgeHardening')
        Get-SessionRestoreHistoryText -Session $restored[0] |
            Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(DNS, EdgeHardening\)$'
    }

    It 'reports a newer overlapping module session under StrictMode' {
        # NoIDPrivacy.ps1 runs under Set-StrictMode -Version Latest. Module
        # manifests carry no 'recordType', so an unguarded read of it throws into
        # the per-candidate catch and silently drops every neighbour.
        Set-StrictMode -Version Latest

        $backupRoot = Join-Path $TestDrive 'Backups'
        $older = Join-Path $backupRoot 'Session_20260712_035112_343_b1321e36'
        $newer = Join-Path $backupRoot 'Session_20260712_041500_000_c2432f47'
        foreach ($pair in @(
                @{ Path = $older; Id = 'Session_20260712_035112_343_b1321e36'; Stamp = '2026-07-12T03:51:12.3430000+02:00' }
                @{ Path = $newer; Id = 'Session_20260712_041500_000_c2432f47'; Stamp = '2026-07-12T04:15:00.0000000+02:00' }
            )) {
            $null = New-Item -Path $pair.Path -ItemType Directory -Force
            [PSCustomObject]@{
                schemaVersion = 2
                sessionId     = $pair.Id
                timestamp     = $pair.Stamp
                modules       = @([PSCustomObject]@{ name = 'DNS' })
            } | ConvertTo-Json -Depth 6 |
                Set-Content -LiteralPath (Join-Path $pair.Path 'manifest.json') -Encoding UTF8
        }

        $script:NoticeLines = [System.Collections.Generic.List[string]]::new()
        Mock Write-Log { $script:NoticeLines.Add([string]$Message) }
        Mock Write-RestoreLog { }

        $olderManifest = Get-SessionManifest -SessionPath $older
        Write-NewerModuleSessionNotice `
            -SessionPath $older `
            -Manifest $olderManifest `
            -ModuleNames @('DNS')

        ($script:NoticeLines -join "`n") | Should -Match 'older than 1 session'
        ($script:NoticeLines -join "`n") | Should -Match 'Session_20260712_041500_000_c2432f47: DNS'
    }

    It 'never gates a module restore on the restore receipt' {
        $source = Get-Content -LiteralPath (Join-Path $repoRoot 'Core/Rollback.ps1') -Raw -Encoding UTF8
        $source | Should -Not -Match 'Every requested module in this session has already been restored'
        $source | Should -Not -Match 'Requested module has already been restored'
        $source | Should -Not -Match 'module:\$\(\[string\]\$_\.name\)" -notin \$restoredScopes'
        $source | Should -Match 'This session contains no modules to restore'
    }

    It 'refuses to traverse a reparse-point backup root' {
        $source = Get-Content -LiteralPath (Join-Path $repoRoot 'Core/Rollback.ps1') -Raw
        $source | Should -Match 'Get-Item -LiteralPath \$BackupDirectory -Force -ErrorAction Stop'
        $source | Should -Match 'Backup root is a reparse point and cannot be traversed safely'
    }
}
