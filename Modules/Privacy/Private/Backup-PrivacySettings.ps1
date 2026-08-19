function Backup-PrivacySettings {
    <#
    .SYNOPSIS
        Captures the exact prestate of every target selected for this Privacy run.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Back up exact Privacy prestate')) { return }

    $result = [PSCustomObject]@{
        Success = $false; Count = 0; SnapshotPath = $null
        BloatwareActionLogPath = $null; Tier1AppInventoryPath = $null
        Failures = [System.Collections.Generic.List[string]]::new()
    }
    try {
        $runtimePlan = Get-PrivacyRuntimeTargetPlan -Config $Config
        $plan = $runtimePlan.RegistryPlan
        $targets = @($plan.ApplicableTargets)
        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($target in $targets) {
            try {
                $entry = [PSCustomObject]@{
                    Path = $target.Path; Name = $target.Name
                    ApplyType = $target.Type; ApplyValue = $target.Value
                    KeyExisted = $false; Exists = $false; Type = $null; Value = $null
                }
                if (Test-Path -LiteralPath $target.Path -PathType Container) {
                    $entry.KeyExisted = $true
                    $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                    if ($key.GetValueNames() -contains [string]$target.Name) {
                        $entry.Exists = $true
                        $entry.Type = $key.GetValueKind([string]$target.Name).ToString()
                        $entry.Value = $key.GetValue([string]$target.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    }
                }
                $entries.Add($entry)
            }
            catch { $result.Failures.Add("Privacy prestate read failed for $($target.Path)::$($target.Name): $($_.Exception.Message)") }
        }
        if ($result.Failures.Count -gt 0 -or $entries.Count -ne $targets.Count) {
            throw "Privacy registry prestate is incomplete: $($result.Failures -join '; ')"
        }

        # Ancestor levels that New-Item -Force will create implicitly during
        # Apply (e.g. ...\Windows\Appx when the target key is ...\Appx\
        # RemoveDefaultMicrosoftStorePackages). They were in no entry's Path, so
        # Restore's key-existence map never visited them and an "exact" restore
        # left empty NoID-created policy keys behind. Walk each absent target
        # key up to its first pre-existing ancestor and seal every missing
        # level; Restore folds them into the same existence machinery as the
        # target keys themselves.
        $declaredPathSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) { $null = $declaredPathSet.Add([string]$entry.Path) }
        $absentAncestorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @($entries | Where-Object { -not [bool]$_.KeyExisted })) {
            $ancestorPath = Split-Path -Path ([string]$entry.Path) -Parent
            while (-not [string]::IsNullOrWhiteSpace($ancestorPath) -and
                $ancestorPath.Contains('\') -and
                -not $declaredPathSet.Contains($ancestorPath) -and
                -not (Test-Path -LiteralPath $ancestorPath -PathType Container)) {
                $null = $absentAncestorKeys.Add($ancestorPath)
                $ancestorPath = Split-Path -Path $ancestorPath -Parent
            }
        }

        # AppX removal can delete package-capability firewall values belonging
        # to other local users as well as the selected Explorer user. Bind the
        # complete pre-removal rule set for the sealed package families into
        # the exact Privacy prestate before any mutation occurs.
        $tier2Selected = [bool]($Config.PSObject.Properties['Tier2BloatwareRemovalSelected'] -and
            $Config.Tier2BloatwareRemovalSelected)
        $weatherWidgetSelected = [bool]($Config.PSObject.Properties['WeatherWidgetRemovalSelected'] -and
            $Config.WeatherWidgetRemovalSelected)
        $actionLog = $null
        $appxFirewallFamilies = @()
        if ($tier2Selected) {
            $actionLog = Get-PrivacyBloatwareActionLog -IncludeWeatherWidget $weatherWidgetSelected
            $null = Assert-PrivacyBloatwareActionLog -ActionLog $actionLog
            $appxFirewallFamilies = @(Get-PrivacyAppxOrdinalUniqueStrings -Values @(
                    $actionLog.Entries | Where-Object { [bool]$_.Present } |
                        ForEach-Object { [string]$_.PackageFamilyName }
                ))
        }
        $appxFirewallState = Get-PrivacyAppxFirewallState -PackageFamilyNames $appxFirewallFamilies

        $snapshot = [PSCustomObject]@{
            SchemaVersion = 7
            # Additive, presence-gated: schema 7 stays the decision-bound
            # contract every -eq 7 gate in Apply/Restore/Rollback relies on.
            AbsentAncestorKeys = @($absentAncestorKeys | Sort-Object)
            Mode = [string]$Config.Mode
            InteractiveUserSid = [string](Get-PrivacyUserContext).Sid
            EditionFamily = [string]$plan.Applicability.EditionFamily
            BuildNumber = [int]$plan.Applicability.BuildNumber
            DomainJoined = [bool]$plan.Applicability.DomainJoined
            MdmRegistered = [bool]$plan.Applicability.MdmRegistered
            ManagementStateKnown = [bool]$plan.Applicability.ManagementStateKnown
            MultiSession = [bool]$plan.Applicability.MultiSession
            UcpdProtectionStateKnown = [bool]$plan.Applicability.UcpdProtectionStateKnown
            UcpdProtectionActive = [bool]$plan.Applicability.UcpdProtectionActive
            UcpdStatus = [string]$plan.Applicability.UcpdStatus
            Tier1PolicyRemovalSelected = [bool]($Config.PSObject.Properties['Tier1PolicyRemovalSelected'] -and $Config.Tier1PolicyRemovalSelected)
            Tier2BloatwareRemovalSelected = $tier2Selected
            WeatherWidgetRemovalSelected = $weatherWidgetSelected
            AppxFirewallState = $appxFirewallState
            DeclaredRegistryTargetCount = [int]$plan.DeclaredCount
            TargetCount = $targets.Count
            Entries = @($entries)
            NotCheckedRegistryTargets = @($plan.NotCheckedTargets)
            NotApplicableRegistryTargets = @($plan.NotApplicableTargets)
            DeclaredServiceNames = @($runtimePlan.DeclaredServiceNames)
            ApplicableServiceNames = @()
            DeclaredScheduledTaskPaths = @($runtimePlan.DeclaredScheduledTaskPaths)
            ApplicableScheduledTaskPaths = @()
        }
        $null = Assert-PrivacyRegistrySnapshot `
            -Snapshot $snapshot `
            -ExpectedTargets $targets `
            -ExpectedNotCheckedTargets @($plan.NotCheckedTargets) `
            -ExpectedNotApplicableTargets @($plan.NotApplicableTargets)
        $snapshotPath = Register-Backup -Type 'Privacy' -Data $snapshot -Name 'Privacy_PreState'
        if (-not $snapshotPath) { throw 'Privacy prestate registration failed' }
        $result.Count++

        foreach ($serviceName in @($runtimePlan.ApplicableServiceNames)) {
            $serviceBackup = Backup-ServiceConfiguration -ServiceName $serviceName
            if (-not $serviceBackup.Success -or -not $serviceBackup.Exists) { throw "Privacy service backup failed: $serviceName ($($serviceBackup.Error))" }
            $result.Count++
        }

        foreach ($taskPath in @($runtimePlan.ApplicableScheduledTaskPaths)) {
            $taskBackup = Backup-ScheduledTask -TaskPath $taskPath
            if (-not $taskBackup.Success -or -not $taskBackup.Exists) { throw "Privacy scheduled-task backup failed: $taskPath ($($taskBackup.Error))" }
            $result.Count++
        }

        # Tier 1 can cause Windows to remove apps after policy processing. Seal
        # the original user's package identities before Apply so the separate
        # non-exact app-recovery step can later re-register or reinstall only
        # apps which were actually present before this run.
        if ([bool]($Config.PSObject.Properties['Tier1PolicyRemovalSelected'] -and $Config.Tier1PolicyRemovalSelected)) {
            $tier1Inventory = Get-PrivacyTier1AppInventory
            $null = Assert-PrivacyTier1AppInventory -Inventory $tier1Inventory
            $tier1InventoryPath = Register-Backup -Type 'Privacy' -Data $tier1Inventory -Name 'Privacy_Tier1AppInventory'
            if (-not $tier1InventoryPath) { throw 'Privacy Tier 1 app-inventory registration failed' }
            $roundTripTier1 = Get-Content -LiteralPath $tier1InventoryPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $null = Assert-PrivacyTier1AppInventory -Inventory $roundTripTier1
            if ([string]$roundTripTier1.InteractiveUserSid -cne [string]$snapshot.InteractiveUserSid) {
                throw 'Privacy Tier 1 app inventory user differs from the registry prestate user'
            }
            $result.Tier1AppInventoryPath = $tier1InventoryPath
            $result.Count++
        }

        # Tier 2 classic bloatware removal (all editions, best-effort, NOT an exact
        # restore): seal the exact pre-removal action log BEFORE Apply removes
        # anything. The session restore engine never replays this artifact
        # automatically -- see Assert-PrivacyBloatwareActionLog and Restore-BloatwareApps.
        if ($tier2Selected) {
            $actionLogPath = Register-Backup -Type 'Privacy' -Data $actionLog -Name 'Privacy_BloatwareActions'
            if (-not $actionLogPath) { throw 'Privacy Tier 2 bloatware action-log registration failed' }
            $roundTripLog = Get-Content -LiteralPath $actionLogPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $null = Assert-PrivacyBloatwareActionLog -ActionLog $roundTripLog
            if ([string]$roundTripLog.InteractiveUserSid -cne [string]$snapshot.InteractiveUserSid) {
                throw 'Privacy Tier 2 action log user differs from the registry prestate user'
            }
            $result.BloatwareActionLogPath = $actionLogPath
            $result.Count++
        }

        $snapshot.ApplicableServiceNames = @($runtimePlan.ApplicableServiceNames)
        $snapshot.ApplicableScheduledTaskPaths = @($runtimePlan.ApplicableScheduledTaskPaths)
        [System.IO.File]::WriteAllText(
            $snapshotPath,
            ($snapshot | ConvertTo-Json -Depth 20),
            [System.Text.UTF8Encoding]::new($false)
        )
        $roundTrip = Get-Content -LiteralPath $snapshotPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-PrivacyRegistrySnapshot `
            -Snapshot $roundTrip `
            -ExpectedTargets $targets `
            -ExpectedNotCheckedTargets @($plan.NotCheckedTargets) `
            -ExpectedNotApplicableTargets @($plan.NotApplicableTargets)
        $result.SnapshotPath = $snapshotPath

        $result.Success = ($result.Count -gt 0 -and $result.Failures.Count -eq 0)
        Write-Log -Level SUCCESS -Message "Exact Privacy prestate captured ($($targets.Count) applicable registry targets, $(@($plan.NotApplicableTargets).Count) not applicable, $($result.Count) sealed artifacts)" -Module 'Privacy'
    }
    catch {
        $result.Failures.Add($_.Exception.Message)
        Write-Log -Level ERROR -Message "Privacy backup failed: $($_.Exception.Message)" -Module 'Privacy'
    }
    return $result
}
