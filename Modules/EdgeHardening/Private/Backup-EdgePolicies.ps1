<#
.SYNOPSIS
    Back up the exact Edge policy values this module will mutate.

.DESCRIPTION
    Captures value existence, registry type, value data, and original key
    existence for every selected Edge policy. The resulting JSON artifact is
    registered in the active BAVR session and is the canonical restore source.
#>

function Backup-EdgePolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupName = 'EdgeHardening_PreState',

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RuntimeApplicability,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$EdgeInstallationStatus
    )

    $result = [PSCustomObject]@{
        Success         = $false
        BackupPath      = $null
        DeclaredTargets  = 0
        TargetsBackedUp = 0
        NotApplicable    = 0
        Errors          = @()
    }

    if (-not $PSCmdlet.ShouldProcess('HKLM:\Software\Policies\Microsoft\Edge', 'Back up selected Edge policy pre-state')) {
        return $result
    }

    try {
        foreach ($requiredCommand in @('Register-Backup')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                throw "Required BAVR command is unavailable: $requiredCommand"
            }
        }

        foreach ($requiredCommand in @('Get-EdgePolicyTargets', 'Assert-EdgePolicySnapshot')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                throw "Required Edge BAVR command is unavailable: $requiredCommand"
            }
        }
        $targetPlan = @(Get-EdgePolicyTargets -AllowExtensions:$AllowExtensions `
                -RuntimeApplicability $RuntimeApplicability -EdgeInstallationStatus $EdgeInstallationStatus)
        $targets = @($targetPlan | Where-Object { [bool]$_.Applicable })
        $notApplicable = @($targetPlan | Where-Object { -not [bool]$_.Applicable })

        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($target in $targets) {
            $path = [string]$target.Path
            $name = [string]$target.Name
            $keyExisted = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
            $valueExisted = $false
            $value = $null
            $valueType = $null
            if ($keyExisted) {
                $registryKey = Get-Item -LiteralPath $path -ErrorAction Stop
                $valueExisted = $registryKey.GetValueNames() -contains $name
                if ($valueExisted) {
                    $value = $registryKey.GetValue(
                        $name,
                        $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $valueType = $registryKey.GetValueKind($name).ToString()
                }
            }

            $entries.Add([PSCustomObject]@{
                    Path       = $path
                    Name       = $name
                    KeyExisted = [bool]$keyExisted
                    Exists     = [bool]$valueExisted
                    Type       = $valueType
                    Value      = $value
                    ApplyType  = [string]$target.Type
                    ApplyValue = $target.Value
                })
        }

        if ($entries.Count -eq 0) {
            throw 'No selected Edge policy targets were available for backup'
        }

        $snapshot = [PSCustomObject]@{
            SchemaVersion      = 6
            CapturedAt         = (Get-Date).ToUniversalTime().ToString('o')
            AllowExtensions    = [bool]$AllowExtensions
            RuntimeApplicability = $RuntimeApplicability
            EdgeInstallationStatus = $EdgeInstallationStatus
            DeclaredTargetCount = $targetPlan.Count
            TargetCount        = $entries.Count
            NotApplicableCount = $notApplicable.Count
            NotApplicable      = @($notApplicable | ForEach-Object {
                    [PSCustomObject]@{
                        Path = [string]$_.Path
                        Name = [string]$_.Name
                        Reason = [string]$_.NotApplicableReason
                    }
                })
            Entries            = @($entries)
        }
        $null = Assert-EdgePolicySnapshot -Snapshot $snapshot
        $backupPath = Register-Backup -Type 'EdgeHardening' -Data $snapshot -Name $BackupName
        if (-not $backupPath -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf -ErrorAction Stop)) {
            throw 'Edge pre-state registration did not create an artifact'
        }

        $roundTrip = Get-Content -LiteralPath $backupPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $null = Assert-EdgePolicySnapshot -Snapshot $roundTrip

        $result.Success = $true
        $result.BackupPath = $backupPath
        $result.DeclaredTargets = $targetPlan.Count
        $result.TargetsBackedUp = $entries.Count
        $result.NotApplicable = $notApplicable.Count
        Write-Log -Level SUCCESS -Message "Edge pre-state backed up for $($entries.Count)/$($targetPlan.Count) applicable selected policy values; NotApplicable=$($notApplicable.Count)" -Module 'EdgeHardening'
    }
    catch {
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Edge policy backup failed: $($_.Exception.Message)" -Module 'EdgeHardening'
    }

    return $result
}
