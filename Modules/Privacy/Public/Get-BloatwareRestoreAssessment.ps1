#Requires -Version 5.1

function Get-BloatwareRestoreAssessment {
    <#
    .SYNOPSIS
        Read-only assessment of whether a sealed Privacy session needs app work.

    .DESCRIPTION
        Validates the complete sealed session and every available Tier 1/Tier 2
        app inventory, requires the original interactive user for current AppX
        inspection, and deduplicates overlapping app identities. A recorded
        package-family identity enables local re-registration; a verified Store
        mapping enables the winget fallback. This function never changes state.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $details = [System.Collections.Generic.List[string]]::new()
    $result = [PSCustomObject]@{
        Success = $false
        Status = 'Failed'
        SessionPath = ''
        OriginalUserSid = ''
        CurrentUserSid = ''
        RecordedPresent = 0
        Tier1RecordedPresent = 0
        Tier2RecordedPresent = 0
        Mapped = 0
        LocalRegisterable = 0
        StoreMapped = 0
        Missing = 0
        AlreadyPresent = 0
        Unmapped = 0
        MissingApps = @()
        AlreadyPresentApps = @()
        UnmappedApps = @()
        Error = ''
        Details = $details
    }

    try {
        $repoRoot = Split-Path (Split-Path $script:ModuleRoot -Parent) -Parent
        if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            . (Join-Path $repoRoot 'Core\Logger.ps1')
            Initialize-Logger -EnableConsole $true -EnableFile $false
        }
        # A successful exact module restore writes the canonical receipt before
        # this separately-invoked original-user app recovery runs. Rollback's
        # sealed-session validator deliberately refuses to accept that file
        # without the canonical receipt parser. The full framework already
        # loads QuickActions first; make the public standalone Privacy command
        # establish the same trust boundary instead of failing only after a
        # real Restore has created its receipt.
        if (-not (Get-Command Get-SessionRestoreReceipt -ErrorAction SilentlyContinue)) {
            . (Join-Path $repoRoot 'Core\QuickActions.ps1')
        }
        foreach ($requiredCommand in @('Get-SessionManifest','Assert-SessionManifest','Resolve-SessionChildPath')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                . (Join-Path $repoRoot 'Core\Rollback.ps1')
                break
            }
        }

        $resolvedSession = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SessionPath -ErrorAction Stop).Path)
        $result.SessionPath = $resolvedSession
        $result.CurrentUserSid = Get-PrivacyCurrentProcessUserSid

        $manifest = Get-SessionManifest -SessionPath $resolvedSession
        Assert-SessionManifest -SessionPath $resolvedSession -Manifest $manifest -RequestedModules @('Privacy')
        $privacyInfo = @($manifest.modules | Where-Object { [string]$_.name -eq 'Privacy' })
        if ($privacyInfo.Count -ne 1) {
            throw 'The sealed session does not contain exactly one Privacy module record'
        }

        $inventoryDefinitions = @(
            [PSCustomObject]@{
                Name = 'Privacy_Tier1AppInventory'
                Tier = 'Tier1'
                Validator = 'Assert-PrivacyTier1AppInventory'
            },
            [PSCustomObject]@{
                Name = 'Privacy_BloatwareActions'
                Tier = 'Tier2'
                Validator = 'Assert-PrivacyBloatwareActionLog'
            }
        )
        $inventories = [System.Collections.Generic.List[object]]::new()
        foreach ($definition in $inventoryDefinitions) {
            $artifacts = @($privacyInfo[0].artifacts | Where-Object {
                    [string]$_.type -eq 'Privacy' -and [string]$_.name -eq [string]$definition.Name
                })
            if ($artifacts.Count -gt 1) {
                throw "The sealed session contains an ambiguous $($definition.Tier) app inventory"
            }
            if ($artifacts.Count -eq 0) { continue }

            $inventoryPath = Resolve-SessionChildPath `
                -SessionPath $resolvedSession `
                -RelativePath ([string]$artifacts[0].relativePath)
            $inventory = Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            if ([string]$definition.Validator -eq 'Assert-PrivacyTier1AppInventory') {
                $null = Assert-PrivacyTier1AppInventory -Inventory $inventory
            }
            else {
                $null = Assert-PrivacyBloatwareActionLog -ActionLog $inventory
            }
            $inventories.Add([PSCustomObject]@{
                    Tier = [string]$definition.Tier
                    UserSid = [string]$inventory.InteractiveUserSid
                    Entries = @($inventory.Entries)
                })
        }

        if ($inventories.Count -eq 0) {
            $result.Success = $true
            $result.Status = 'NothingToDo'
            $details.Add('The validated session contains no Tier 1 or Tier 2 app inventory.')
            return $result
        }

        $userSids = @($inventories.UserSid | Sort-Object -Unique)
        if ($userSids.Count -ne 1) {
            throw 'The sealed Tier 1/Tier 2 app inventories belong to different users'
        }
        $result.OriginalUserSid = [string]$userSids[0]
        if ($result.CurrentUserSid -cne $result.OriginalUserSid) {
            $result.Status = 'OriginalUserRequired'
            $result.Error = "App restore assessment must run as the original interactive user SID $($result.OriginalUserSid), not $($result.CurrentUserSid)."
            $details.Add($result.Error)
            return $result
        }

        foreach ($inventory in @($inventories)) {
            $recorded = @($inventory.Entries | Where-Object { [bool]$_.Present } | Group-Object AppName).Count
            if ([string]$inventory.Tier -eq 'Tier1') { $result.Tier1RecordedPresent = $recorded }
            else { $result.Tier2RecordedPresent = $recorded }
        }

        $allEntries = @($inventories | ForEach-Object { @($_.Entries) })
        # A legacy inventory remains readable for its sealed local package
        # families, but a Store fallback is executable only while the same
        # exact ID/package contract is still present in today's audited map.
        # This prevents an old session from re-enabling a recovery route that
        # a later release gate has explicitly withdrawn.
        $currentRecoveryConfig = Get-PrivacyBloatwareConfig
        $descriptors = [System.Collections.Generic.List[object]]::new()
        foreach ($group in @($allEntries | Group-Object AppName)) {
            $states = @($group.Group | ForEach-Object { [bool]$_.Present } | Select-Object -Unique)
            if ($states.Count -ne 1) {
                throw "The sealed Tier 1/Tier 2 inventories disagree about the original state of $($group.Name)"
            }
            if (-not [bool]$states[0]) { continue }

            $storeIds = @($group.Group | ForEach-Object { [string]$_.StoreId } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            if ($storeIds.Count -gt 1) {
                throw "The sealed Tier 1/Tier 2 inventories disagree about the Store identity of $($group.Name)"
            }
            $expectedNames = @($group.Group | ForEach-Object { @($_.ExpectedPackageNames) } |
                ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Sort-Object -Unique)
            $familyNames = @($group.Group | ForEach-Object { [string]$_.PackageFamilyName } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            $verificationNames = if ($expectedNames.Count -gt 0) { @($expectedNames) } else { @([string]$group.Name) }
            $currentMapping = $currentRecoveryConfig.Mappings.([string]$group.Name)
            $canUseStore = ($storeIds.Count -eq 1 -and $expectedNames.Count -gt 0 -and
                $null -ne $currentMapping -and
                [string]$currentMapping.StoreId -ceq [string]$storeIds[0] -and
                (@($currentMapping.ExpectedPackageNames | Sort-Object) -join ([char]31)) -ceq
                    (@($expectedNames | Sort-Object) -join ([char]31)))
            $canRegisterLocally = ($familyNames.Count -gt 0)
            $descriptors.Add([PSCustomObject]@{
                    AppName = [string]$group.Name
                    StoreId = if ($storeIds.Count -eq 1) { [string]$storeIds[0] } else { '' }
                    ExpectedPackageNames = @($expectedNames)
                    VerificationPackageNames = @($verificationNames)
                    PackageFamilyNames = @($familyNames)
                    CanRegisterLocally = $canRegisterLocally
                    CanUseStore = $canUseStore
                })
        }

        $restorableApps = @($descriptors | Where-Object { $_.CanRegisterLocally -or $_.CanUseStore })
        $unmappedApps = @($descriptors | Where-Object { -not $_.CanRegisterLocally -and -not $_.CanUseStore })
        $result.RecordedPresent = $descriptors.Count
        $result.Mapped = $restorableApps.Count
        $result.LocalRegisterable = @($descriptors | Where-Object CanRegisterLocally).Count
        $result.StoreMapped = @($descriptors | Where-Object CanUseStore).Count
        $result.Unmapped = $unmappedApps.Count
        $result.UnmappedApps = @($unmappedApps)

        $missingApps = [System.Collections.Generic.List[object]]::new()
        $alreadyPresentApps = [System.Collections.Generic.List[object]]::new()
        foreach ($app in $restorableApps) {
            try {
                $registered = @($app.VerificationPackageNames | ForEach-Object {
                        @(Get-AppxPackage -Name $_ -ErrorAction Stop)
                    })
            }
            catch {
                throw "Current AppX registration query failed for $($app.AppName): $($_.Exception.Message)"
            }
            if ($registered.Count -gt 0) { $alreadyPresentApps.Add($app) }
            else { $missingApps.Add($app) }
        }

        $result.MissingApps = @($missingApps)
        $result.AlreadyPresentApps = @($alreadyPresentApps)
        $result.Missing = $missingApps.Count
        $result.AlreadyPresent = $alreadyPresentApps.Count
        $result.Success = $true
        $result.Status = if ($result.Missing -gt 0) {
            'Needed'
        }
        elseif ($result.Unmapped -gt 0) {
            'UnmappedOnly'
        }
        else {
            'NothingToDo'
        }

        $details.Add("Privacy app assessment: recorded=$($result.RecordedPresent), restorable=$($result.Mapped), local=$($result.LocalRegisterable), Store=$($result.StoreMapped), missing=$($result.Missing), already present=$($result.AlreadyPresent), no route=$($result.Unmapped).")
        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
        $details.Add($result.Error)
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Privacy app restore assessment failed: $($result.Error)" -Module 'Privacy'
        }
        return $result
    }
}
